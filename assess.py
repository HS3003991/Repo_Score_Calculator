#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from security_score import SEVERITIES, Config, config_from_dict, density, normalize_severity, strict_cdf, weighted_count
from build_benchmark import GitHubClient, Toolchain, check_tools, cloc_to_loc_by_language

BENCH_DIR = Path("benchmarks")
LAYERS = ["SAST", "SCA", "IaC"]

IAC_CLOC_LANGUAGES = ["Dockerfile", "YAML"]


def _json_default(value):
    """Ersatzwert fuer Objekte, die json nicht direkt serialisieren kann. Gibt schlicht den Text 'inf' zurueck."""
    return "inf"


def _repo_stars(repo: dict) -> int:
    """Liefert die Sternanzahl eines Repo-Eintrags (0, falls nicht vorhanden). Dient zum Sortieren nach Popularitaet."""
    return repo.get("stars", 0)

DEFAULT_BENCHMARK_REPOS = 100

LANGUAGE_PROFILES: dict[str, dict] = {
    "python": {
        "github_query": "language:Python stars:>1000",
        "cloc_languages": ["Python"],
        "extensions": [".py", ".pyi"],
        "sca_types": ["pip", "poetry", "pipenv", "python-pkg", "conda"],
        "dep_ecosystem": "python",
    },
    "typescript": {
        "github_query": "language:TypeScript stars:>1000",
        "cloc_languages": ["TypeScript", "JavaScript", "JSX"],
        "extensions": [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
        "sca_types": ["npm", "yarn", "pnpm", "node-pkg"],
        "dep_ecosystem": "node",
    },
    "javascript": {
        "github_query": "language:JavaScript stars:>1000",
        "cloc_languages": ["JavaScript", "JSX"],
        "extensions": [".js", ".jsx", ".mjs", ".cjs"],
        "sca_types": ["npm", "yarn", "pnpm", "node-pkg"],
        "dep_ecosystem": "node",
    },
}


def language_of_path(path: Optional[str]) -> Optional[str]:
    """Ordnet einen Dateipfad anhand seiner Endung einer Sprache zu. Gibt den Sprachschluessel oder None zurueck."""
    if not path:
        return None
    suffix = Path(path).suffix.lower()
    for lang, prof in LANGUAGE_PROFILES.items():
        if suffix in prof["extensions"]:
            return lang
    return None


def _language_of_sca_type(trivy_type: Optional[str]) -> Optional[str]:
    """Bildet einen Trivy-Pakettyp (z. B. pip, npm) auf eine Sprache ab. Gibt den Sprachschluessel oder None zurueck."""
    if not trivy_type:
        return None
    t = str(trivy_type).lower()
    for lang, prof in LANGUAGE_PROFILES.items():
        if t in prof["sca_types"]:
            return lang
    return None


def _empty_counts() -> dict[str, int]:
    """Liefert ein leeres Severity-Zaehlwerk mit allen Schweregraden auf 0."""
    return {s: 0 for s in SEVERITIES}


def semgrep_counts_by_language(semgrep_json: Path, cfg: Config,
                               exclude: Optional[re.Pattern]) -> dict[str, dict[str, int]]:
    """Liest die Semgrep-Ausgabe und zaehlt Funde je Sprache und Schweregrad. Ausgeschlossene Pfade werden ignoriert."""
    out = {lang: _empty_counts() for lang in LANGUAGE_PROFILES}
    data = json.loads(Path(semgrep_json).read_text(encoding="utf-8"))
    for res in data.get("results", []):
        p = res.get("path")
        if exclude is not None and p and exclude.search(p):
            continue
        lang = language_of_path(p)
        if lang is None:
            continue
        sev = normalize_severity(res.get("extra", {}).get("severity"), cfg.semgrep_severity_map)
        if sev:
            out[lang][sev] += 1
    return out


def trivy_sca_by_language_and_iac(trivy_json: Path, cfg: Config, exclude: Optional[re.Pattern]
                                  ) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    """Liefert (sca_counts_je_sprache, iac_counts_gesamt).

    Kein Datums-Filter: es werden alle von Trivy gemeldeten CVEs gezaehlt. Eine
    eventuelle zeitliche Eingrenzung (Stichtag) erfolgt bewusst NICHT in diesem
    Tool, sondern erst spaeter in der Auswertung der Arbeit.
    """
    sca = {lang: _empty_counts() for lang in LANGUAGE_PROFILES}
    iac = _empty_counts()
    data = json.loads(Path(trivy_json).read_text(encoding="utf-8"))
    for r in data.get("Results", []):
        if exclude is not None and r.get("Target") and exclude.search(r["Target"]):
            continue
        lang = _language_of_sca_type(r.get("Type"))
        for v in r.get("Vulnerabilities", []) or []:
            if lang is None:
                continue
            sev = normalize_severity(v.get("Severity"), cfg.trivy_severity_map)
            if sev:
                sca[lang][sev] += 1
        for m in r.get("Misconfigurations", []) or []:
            sev = normalize_severity(m.get("Severity"), cfg.trivy_severity_map)
            if sev:
                iac[sev] += 1
    return sca, iac


def loc_for_language(loc_by_language: dict[str, int], lang: str) -> int:
    """Summiert die Codezeilen aller cloc-Sprachen, die zum Sprachprofil gehoeren. Gibt die LoC dieser Sprache zurueck."""
    return sum(loc_by_language.get(n, 0) for n in LANGUAGE_PROFILES[lang]["cloc_languages"])


def iac_loc(loc_by_language: dict[str, int]) -> int:
    """Summiert die Codezeilen der IaC-relevanten cloc-Sprachen (Dockerfile, YAML)."""
    return sum(loc_by_language.get(n, 0) for n in IAC_CLOC_LANGUAGES)


def count_dependencies(repo: Path, ecosystem: str) -> int:
    """Zaehlt die Abhaengigkeiten eines Repos, bevorzugt aus Lockfiles (inkl. transitiver), sonst aus Manifesten. Gibt die Anzahl zurueck."""
    total = 0
    if ecosystem == "python":
        for lock in repo.rglob("poetry.lock"):
            try:
                total += lock.read_text(encoding="utf-8").count("[[package]]")
            except Exception:
                pass
        if total == 0:
            for req in repo.rglob("requirements*.txt"):
                try:
                    for line in req.read_text(encoding="utf-8").splitlines():
                        s = line.strip()
                        if s and not s.startswith("#") and not s.startswith("-"):
                            total += 1
                except Exception:
                    pass
    elif ecosystem == "node":
        for lock in repo.rglob("package-lock.json"):
            if "node_modules" in str(lock):
                continue
            try:
                d = json.loads(lock.read_text(encoding="utf-8"))
                pkgs = d.get("packages")
                total += (sum(1 for k in pkgs if k) if isinstance(pkgs, dict)
                          else len(d.get("dependencies", {})))
            except Exception:
                pass
        if total == 0:
            for pj in repo.rglob("package.json"):
                if "node_modules" in str(pj):
                    continue
                try:
                    d = json.loads(pj.read_text(encoding="utf-8"))
                    total += len(d.get("dependencies", {})) + len(d.get("devDependencies", {}))
                except Exception:
                    pass
    return total


def make_metrics(sast_counts: dict, loc: int, sca_counts: dict, deps: int,
                 iac_counts: dict, iacloc: int, cfg: Config) -> dict:
    """Berechnet aus Fund-Zählwerk und Bezugsgroessen die drei Dichten (SAST/SCA/IaC) eines Repos. Gibt ein Kennzahl-Dict zurück."""
    w = cfg.severity_weights
    return {
        "loc": loc,
        "semgrep": dict(sast_counts),
        "sast_density": density(weighted_count(sast_counts, w), loc / 1000.0),
        "dependencies": deps,
        "sca": dict(sca_counts),
        "sca_density": density(weighted_count(sca_counts, w), deps),
        "iac_loc": iacloc,
        "iac": dict(iac_counts),
        "iac_density": density(weighted_count(iac_counts, w), iacloc / 1000.0),
    }


def benchmark_path(lang: str) -> Path:
    """Liefert den Dateipfad der Sprach-Benchmark fuer die angegebene Sprache."""
    return BENCH_DIR / f"benchmark_{lang}.json"


def benchmark_exists(lang: str) -> bool:
    """Prueft, ob fuer eine Sprache bereits eine Benchmark-Datei vorliegt."""
    return benchmark_path(lang).exists()


def load_benchmark(lang: str) -> list[dict]:
    """Laedt die Repo-Liste der Sprach-Benchmark aus der JSON-Datei."""
    return json.loads(benchmark_path(lang).read_text(encoding="utf-8")).get("repos", [])


def save_benchmark(lang: str, repos: list[dict], ruleset: str) -> None:
    """Schreibt die Repo-Liste einer Sprache als Benchmark-JSON auf die Platte."""
    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"language": lang, "ruleset": ruleset, "created": date.today().isoformat(),
               "benchmark_size": len(repos), "repos": repos}
    benchmark_path(lang).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default),
        encoding="utf-8")


def iac_benchmark_path() -> Path:
    """Liefert den Dateipfad der separaten, sprachunabhaengigen IaC-Benchmark."""
    return BENCH_DIR / "benchmark_iac.json"


def load_iac_benchmark() -> list[dict]:
    """Laedt die Eintraege der IaC-Benchmark, oder eine leere Liste wenn keine existiert."""
    p = iac_benchmark_path()
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8")).get("repos", [])


def save_iac_benchmark(repos: list[dict]) -> None:
    """Schreibt die IaC-Benchmark als JSON auf die Platte."""
    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"layer": "iac", "created": date.today().isoformat(),
               "benchmark_size": len(repos), "repos": repos}
    iac_benchmark_path().write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default),
        encoding="utf-8")


def _iac_entry(repo: dict, source_language: str) -> dict:
    """Baut aus einem Repo-Eintrag einen schlanken IaC-Benchmark-Eintrag (Name, Quelle, LoC, Dichte)."""
    return {"name": repo.get("name"), "source_language": source_language,
            "iac_loc": repo.get("iac_loc", 0), "iac": repo.get("iac", {}),
            "iac_density": repo.get("iac_density", 0.0)}


def merge_into_iac_benchmark(new_entries: list[dict]) -> tuple[int, int]:
    """Fuegt IaC-Eintraege hinzu (dedupliziert nach Repo-Name). Gibt
    (neu_hinzugefuegt, gesamt) zurueck."""
    by_name = {e["name"]: e for e in load_iac_benchmark()}
    added = 0
    for e in new_entries:
        if e["name"] not in by_name:
            added += 1
        by_name[e["name"]] = e
    save_iac_benchmark(list(by_name.values()))
    return added, len(by_name)


def export_iac_benchmark() -> tuple[int, int, int]:
    """Zieht die IaC-Daten aus allen vorhandenen Sprach-Benchmarks und schreibt
    sie in benchmark_iac.json. Beruecksichtigt nur Repos mit IaC-Artefakten
    (iac_loc > 0). Gibt (geprueft, neu, gesamt) zurueck."""
    entries: list[dict] = []
    for lang in LANGUAGE_PROFILES:
        p = benchmark_path(lang)
        if not p.exists():
            continue
        repos = json.loads(p.read_text(encoding="utf-8")).get("repos", [])
        for r in repos:
            if r.get("iac_loc", 0) > 0:
                entries.append(_iac_entry(r, lang))
    added, total = merge_into_iac_benchmark(entries)
    return len(entries), added, total


def measure_repo(repo: Path, lang: str, tools: Toolchain, cfg: Config,
                 exclude: Optional[re.Pattern]) -> dict:
    """Scannt ein einzelnes Benchmark-Repo mit Semgrep und Trivy und berechnet seine Kennzahlen. Gibt das Metrik-Dict zurueck."""
    sem_out, tri_out = repo.parent / "_semgrep.json", repo.parent / "_trivy.json"
    tools.semgrep(repo, sem_out)
    tools.trivy(repo, tri_out)
    loc_by_lang = cloc_to_loc_by_language(tools.cloc(repo))

    sast = semgrep_counts_by_language(sem_out, cfg, exclude)[lang]
    sca_by_lang, iac = trivy_sca_by_language_and_iac(tri_out, cfg, exclude)
    return make_metrics(
        sast_counts=sast, loc=loc_for_language(loc_by_lang, lang),
        sca_counts=sca_by_lang[lang], deps=count_dependencies(repo, LANGUAGE_PROFILES[lang]["dep_ecosystem"]),
        iac_counts=iac, iacloc=iac_loc(loc_by_lang), cfg=cfg)


def build_language_benchmark(lang: str, count: int, gh: GitHubClient, tools: Toolchain,
                             cfg: Config, exclude: Optional[re.Pattern]) -> list[dict]:
    """Sucht die populaersten Repos einer Sprache, vermisst sie und speichert die Benchmark. Repos mit IaC wandern zusaetzlich in die separate IaC-Benchmark."""
    print(f"\n[{lang}] suche {count} populaerste Repos ...")
    repos = gh.search_repositories(LANGUAGE_PROFILES[lang]["github_query"], count)
    collected: list[dict] = []
    for i, r in enumerate(repos, 1):
        workdir = Path(tempfile.mkdtemp(prefix=f"bench_{lang}_"))
        target = workdir / "repo"
        try:
            print(f"  ({i}/{len(repos)}) {r['full_name']} [*{r['stars']}] ...")
            tools.clone(r["clone_url"], target)
            m = measure_repo(target, lang, tools, cfg, exclude)
            collected.append({"name": r["full_name"], "stars": r["stars"], **m})
            print(f"      LoC={m['loc']} SAST_VD={m['sast_density']:.3f} "
                  f"SCA_VD={m['sca_density']:.3f} IaC_VD={m['iac_density']:.3f}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError, KeyError) as e:
            print(f"      uebersprungen: {type(e).__name__} {getattr(e,'stderr','')}",
                  file=sys.stderr)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    save_benchmark(lang, collected, tools.semgrep_config)
    print(f"[{lang}] Benchmark mit {len(collected)} Repos gespeichert ({benchmark_path(lang)}).")

    iac_entries = [_iac_entry(r, lang) for r in collected if r.get("iac_loc", 0) > 0]
    if iac_entries:
        added, total = merge_into_iac_benchmark(iac_entries)
        print(f"[iac] {added} neue IaC-Eintraege ergaenzt (gesamt {total}) "
              f"-> {iac_benchmark_path()}.")
    return collected


def pct_score(value: float, population: list[float]) -> Optional[float]:
    """Bewertet einen Dichtewert per empirischer Verteilungsfunktion gegen eine Referenzverteilung. Gibt einen Score von 0 bis 100 zurueck (hoeher = besser)."""
    if not population:
        return None
    return 100.0 * (1.0 - strict_cdf(value, population))


def _agg(scores_weights: list[tuple[float, float]], weighting: str) -> Optional[float]:
    """Aggregiert mehrere Schicht-Scores gewichtet (gleich oder nach Groesse). Gibt den gewichteten Mittelwert zurueck."""
    items = [(s, w) for s, w in scores_weights if s is not None]
    if not items:
        return None
    if weighting == "loc":
        wsum = sum(w for _, w in items) or 1
        return sum(s * w for s, w in items) / wsum
    return sum(s for s, _ in items) / len(items)


def run_assessment(languages: list[str], target: dict, benchmarks: dict[str, list[dict]],
                   cfg: Config, weighting: str = "loc",
                   iac_benchmark: Optional[list[dict]] = None) -> dict:
    """Bewertet das Ziel-Repo je Schicht und Sprache gegen die Benchmarks und aggregiert zum Gesamtscore. IaC wird bevorzugt gegen die separate IaC-Benchmark verglichen."""
    per_lang: dict[str, dict] = {}
    sast_aw, sca_aw = [], []
    for lang in languages:
        bench = benchmarks.get(lang, [])
        tm = target["languages"][lang]
        s_sast = pct_score(tm["sast_density"], [b["sast_density"] for b in bench])
        s_sca = pct_score(tm["sca_density"], [b["sca_density"] for b in bench])
        per_lang[lang] = {"metrics": tm, "sast_score": s_sast, "sca_score": s_sca,
                          "benchmark_size": len(bench)}
        sast_aw.append((s_sast, tm["loc"]))
        sca_aw.append((s_sca, tm["dependencies"]))

    if iac_benchmark is not None:
        iac_pop = [b["iac_density"] for b in iac_benchmark]
    else:
        iac_pop = [b["iac_density"] for bench in benchmarks.values() for b in bench]
    iac_score = pct_score(target["iac"]["iac_density"], iac_pop)

    layer = {
        "SAST": _agg(sast_aw, weighting),
        "SCA": _agg(sca_aw, weighting),
        "IaC": iac_score,
    }
    num, wsum = 0.0, 0.0
    for L in LAYERS:
        if layer[L] is not None:
            a = cfg.layer_weights.get(L, 0.0)
            num += a * layer[L]
            wsum += a
    si = num / wsum if wsum else None
    return {"per_language": per_lang, "iac": {"density": target["iac"]["iac_density"],
            "score": iac_score, "benchmark_size": len(iac_pop)},
            "layer_scores": layer, "total_score": si}


DEFAULT_IGNORE = (".git", "node_modules", ".venv", "venv", "__pycache__",
                  "dist", "build", ".next", ".cache", ".mypy_cache", ".pytest_cache")


def _copy_for_scan(scan_root: Path, extra_ignore: Optional[list[str]] = None
                   ) -> tuple[Path, Path]:
    """Kopiert scan_root in ein BESCHREIBBARES Temp-Verzeichnis (read-only-Mounts
    wie Docker :ro sind damit unproblematisch) und gibt (work_dir, repo_kopie)
    zurueck. Der Aufrufer muss work_dir aufraeumen. extra_ignore: zusaetzliche
    Ordner-/Datei-Namen (glob), die vom Scan ausgeschlossen werden."""
    work = Path(tempfile.mkdtemp(prefix="scan_"))
    repo = work / "repo"
    patterns = list(DEFAULT_IGNORE) + [p for p in (extra_ignore or []) if p]
    shutil.copytree(scan_root, repo, symlinks=True, ignore_dangling_symlinks=True,
                    ignore=shutil.ignore_patterns(*patterns))
    return work, repo


def scan_target(scan_root: Path, languages: list[str], tools: Toolchain,
                cfg: Config, exclude: Optional[re.Pattern],
                extra_ignore: Optional[list[str]] = None) -> dict:
    """Scannt das Ziel-Repo (als beschreibbare Kopie) mit allen Werkzeugen und berechnet die Kennzahlen je Sprache und fuer IaC. Gibt die Mess-Struktur fuers Scoring zurueck."""
    work, repo = _copy_for_scan(scan_root, extra_ignore)
    try:
        sem_out, tri_out = work / "semgrep.json", work / "trivy.json"
        tools.semgrep(repo, sem_out)
        tools.trivy(repo, tri_out)
        loc_by_lang = cloc_to_loc_by_language(tools.cloc(repo))
        sast = semgrep_counts_by_language(sem_out, cfg, exclude)
        sca_by_lang, iac = trivy_sca_by_language_and_iac(tri_out, cfg, exclude)
        _, _, secrets = _extract_trivy(json.loads(tri_out.read_text(encoding="utf-8")), exclude)
        deps = {lang: count_dependencies(repo, LANGUAGE_PROFILES[lang]["dep_ecosystem"])
                for lang in languages}
    finally:
        shutil.rmtree(work, ignore_errors=True)

    langs: dict[str, dict] = {}
    for lang in languages:
        langs[lang] = make_metrics(
            sast_counts=sast.get(lang, _empty_counts()),
            loc=loc_for_language(loc_by_lang, lang),
            sca_counts=sca_by_lang.get(lang, _empty_counts()),
            deps=deps[lang],
            iac_counts=iac, iacloc=iac_loc(loc_by_lang), cfg=cfg)
    return {"languages": langs,
            "iac": {"iac_density": density(weighted_count(iac, cfg.severity_weights),
                                           iac_loc(loc_by_lang) / 1000.0),
                    "counts": iac, "iac_loc": iac_loc(loc_by_lang)},
            "secrets": {"total": len(secrets), "items": secrets}}


def _run_scanners(scan_root: Path, tools: Toolchain,
                  extra_ignore: Optional[list[str]] = None) -> tuple[dict, dict]:
    """Kopiert das Ziel (read-only-sicher), fuehrt Semgrep + Trivy aus und gibt
    die rohen JSON-Daten beider Scanner zurueck."""
    work, repo = _copy_for_scan(scan_root, extra_ignore)
    try:
        sem_out, tri_out = work / "semgrep.json", work / "trivy.json"
        tools.semgrep(repo, sem_out)
        tools.trivy(repo, tri_out)
        return (json.loads(sem_out.read_text(encoding="utf-8")),
                json.loads(tri_out.read_text(encoding="utf-8")))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _extract_semgrep(data: dict, cfg: Config, exclude: Optional[re.Pattern]) -> list[dict]:
    """Extrahiert die einzelnen Semgrep-Funde mit Pfad, Zeile, Schweregrad und Regel aus der Scanner-Ausgabe."""
    out = []
    for r in data.get("results", []):
        p = r.get("path")
        if exclude is not None and p and exclude.search(p):
            continue
        extra = r.get("extra", {}) or {}
        md = extra.get("metadata", {}) or {}
        raw_sev = extra.get("severity")
        out.append({
            "rule_id": r.get("check_id"),
            "path": p,
            "start_line": (r.get("start") or {}).get("line"),
            "end_line": (r.get("end") or {}).get("line"),
            "severity": normalize_severity(raw_sev, cfg.semgrep_severity_map),
            "severity_raw": raw_sev,
            "message": extra.get("message"),
            "cwe": md.get("cwe"),
            "owasp": md.get("owasp"),
        })
    return out


def _extract_trivy(data: dict, exclude: Optional[re.Pattern]
                   ) -> tuple[list[dict], list[dict], list[dict]]:
    """Extrahiert SCA-, IaC- und Secret-Funde aus der Trivy-Ausgabe. Der eigentliche Secret-Wert wird dabei NICHT uebernommen."""
    sca, iac, secrets = [], [], []
    for r in data.get("Results", []):
        tgt = r.get("Target")
        if exclude is not None and tgt and exclude.search(tgt):
            continue
        typ = r.get("Type")
        for v in r.get("Vulnerabilities", []) or []:
            sca.append({
                "target": tgt, "type": typ,
                "vulnerability_id": v.get("VulnerabilityID"),
                "pkg_name": v.get("PkgName"),
                "installed_version": v.get("InstalledVersion"),
                "fixed_version": v.get("FixedVersion"),
                "severity": v.get("Severity"),
                "title": v.get("Title"),
                "primary_url": v.get("PrimaryURL"),
            })
        for m in r.get("Misconfigurations", []) or []:
            iac.append({
                "target": tgt, "id": m.get("ID") or m.get("AVDID"),
                "severity": m.get("Severity"), "title": m.get("Title"),
                "message": m.get("Message"), "resolution": m.get("Resolution"),
                "primary_url": m.get("PrimaryURL"),
            })
        for s in r.get("Secrets", []) or []:
            secrets.append({
                "target": tgt,
                "rule_id": s.get("RuleID"),
                "category": s.get("Category"),
                "severity": s.get("Severity"),
                "title": s.get("Title"),
                "start_line": s.get("StartLine"),
            })
    return sca, iac, secrets


def _count_by_severity(items: list[dict], key: str = "severity") -> dict:
    """Zaehlt eine Fundliste nach Schweregrad und liefert Gesamtzahl plus Aufschluesselung."""
    counts = {s: 0 for s in SEVERITIES}
    for it in items:
        sev = (it.get(key) or "").upper()
        if sev in counts:
            counts[sev] += 1
    return {"total": len(items), "by_severity": counts}


def build_scan_report(target_label: str, semgrep_data: dict, trivy_data: dict,
                      cfg: Config, exclude: Optional[re.Pattern]) -> dict:
    """Baut aus Semgrep- und Trivy-Ausgabe den kombinierten Schwachstellen-Report mit Zusammenfassung und Einzelfunden."""
    sast = _extract_semgrep(semgrep_data, cfg, exclude)
    sca, iac, secrets = _extract_trivy(trivy_data, exclude)
    return {
        "tool": "secscore-scan",
        "mode": "vulnerability_scan",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "target": target_label,
        "scanners": {"sast": "semgrep", "sca_iac_secrets": "trivy"},
        "semgrep_config": cfg_semgrep_label(cfg),
        "summary": {
            "sast": _count_by_severity(sast),
            "sca": _count_by_severity(sca),
            "iac": _count_by_severity(iac),
            "secrets": {"total": len(secrets)},
        },
        "findings": {"sast": sast, "sca": sca, "iac": iac, "secrets": secrets},
    }


def cfg_semgrep_label(cfg: Config) -> str:
    """Liefert das in der Konfiguration hinterlegte Semgrep-Regelwerk-Label."""
    return getattr(cfg, "semgrep_config", "p/default")


def run_scan_only(scan_root: Path, tools: Toolchain, cfg: Config,
                  exclude: Optional[re.Pattern],
                  extra_ignore: Optional[list[str]] = None) -> dict:
    """Fuehrt einen reinen Schwachstellenscan ohne Scoring durch und liefert den kombinierten Report inklusive Scan-Umfang."""
    semgrep_data, trivy_data = _run_scanners(scan_root, tools, extra_ignore)
    report = build_scan_report(str(scan_root), semgrep_data, trivy_data, cfg, exclude)
    report["scope"] = {"scan_root": str(scan_root),
                       "excluded_dirs": [p for p in (extra_ignore or []) if p]}
    return report


def _json_safe(obj):
    """Ersetzt rekursiv nicht-JSON-faehige Float-Werte (inf/nan) durch Strings. Gibt eine JSON-serialisierbare Struktur zurueck."""
    if isinstance(obj, float):
        if math.isinf(obj):
            return "inf" if obj > 0 else "-inf"
        if math.isnan(obj):
            return "nan"
        return obj
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    return obj


def write_report(report: dict, output: Optional[str], target_path: Path,
                 prefix: str = "scan") -> Optional[str]:
    """Schreibt einen Report als JSON. '-' -> stdout, sonst Default <prefix>-<name>-<ts>.json
    im reports-Ordner; ist --output ein Verzeichnis, wird der Standardname darin verwendet."""
    payload = json.dumps(_json_safe(report), indent=2, ensure_ascii=False)
    if output == "-":
        print(payload)
        return None
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    default_name = f"{prefix}-{target_path.name or 'repo'}-{ts}.json"
    if output:
        path = Path(output)
        if output.endswith(("/", os.sep)) or path.is_dir():
            path = path / default_name
    else:
        path = Path("reports") / default_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    return str(path)


def print_scan_summary(report: dict, out_path: Optional[str]) -> None:
    """Gibt die Severity-Zusammenfassung eines Scan-Reports und den Speicherort auf der Konsole aus."""
    s = report["summary"]
    print("\n" + "=" * 60)
    print("  SCHWACHSTELLENSCAN (ohne Scoring)")
    print("=" * 60)
    print(f"  SAST (Semgrep):     {s['sast']['total']:>4}  "
          f"(C{s['sast']['by_severity']['CRITICAL']} "
          f"H{s['sast']['by_severity']['HIGH']} "
          f"M{s['sast']['by_severity']['MEDIUM']} "
          f"L{s['sast']['by_severity']['LOW']})")
    print(f"  SCA  (Trivy):       {s['sca']['total']:>4}  "
          f"(C{s['sca']['by_severity']['CRITICAL']} "
          f"H{s['sca']['by_severity']['HIGH']} "
          f"M{s['sca']['by_severity']['MEDIUM']} "
          f"L{s['sca']['by_severity']['LOW']})")
    print(f"  IaC  (Trivy):       {s['iac']['total']:>4}  "
          f"(C{s['iac']['by_severity']['CRITICAL']} "
          f"H{s['iac']['by_severity']['HIGH']} "
          f"M{s['iac']['by_severity']['MEDIUM']} "
          f"L{s['iac']['by_severity']['LOW']})")
    print(f"  Secrets (Trivy):    {s['secrets']['total']:>4}")
    print("=" * 60)
    if out_path:
        print(f"  Report gespeichert: {out_path}")


def prompt_mode(preset: Optional[str]) -> str:
    """Ermittelt den Betriebsmodus (Scoring oder reiner Scan), per Flag oder interaktiver Abfrage."""
    if preset:
        return preset
    print("\nWas moechten Sie tun?")
    print("  [1] Scoring-Bewertung (dreischichtiger Score gegen Referenz-Benchmark)")
    print("  [2] Reiner Schwachstellenscan ohne Scoring (kombinierter JSON-Report)")
    ans = _ask("Auswahl (1/2): ")
    return "scan" if ans.strip() == "2" else "score"


def format_secrets_notice(secrets: dict) -> str:
    """Formatiert einen Hinweisblock zu gefundenen Secrets, die NICHT in den Score einfliessen. Bei keinen Funden wird ein leerer String zurueckgegeben."""
    items = secrets.get("items", [])
    if not items:
        return ""
    lines = ["-" * 70,
             f"  HINWEIS: {len(items)} Secret-Fund(e) erkannt - NICHT im Score enthalten:"]
    for s in items:
        loc = f"{s.get('target')}:{s.get('start_line')}" if s.get("start_line") else str(s.get("target"))
        lines.append(f"    - {loc}  {s.get('rule_id')}  [{s.get('severity')}]")
    lines.append("=" * 70)
    return "\n".join(lines)


def format_report(result: dict) -> str:
    """Formatiert das Scoring-Ergebnis als lesbare Konsolentabelle."""
    def f(x):
        """Formatiert einen Dichtewert mit drei Nachkommastellen ('inf' fuer unendlich)."""
        return "inf" if x == float("inf") else f"{x:.3f}"

    def sc(x):
        """Formatiert einen Score zweistellig ('n/a' wenn nicht vorhanden)."""
        return "  n/a" if x is None else f"{x:6.2f}"

    L = ["=" * 70, "  DREISCHICHTIGE SICHERHEITSBEWERTUNG", "=" * 70,
         f"{'Sprache':<11}{'SAST_VD':>9}{'SAST':>7}{'SCA_VD':>9}{'SCA':>7}", "-" * 70]
    for lang, d in result["per_language"].items():
        m = d["metrics"]
        L.append(f"{lang:<11}{f(m['sast_density']):>9}{sc(d['sast_score']):>7}"
                 f"{f(m['sca_density']):>9}{sc(d['sca_score']):>7}")
    L.append("-" * 70)
    L.append(f"IaC (gesamt)  Dichte={f(result['iac']['density'])}  "
             f"Score={sc(result['iac']['score'])}")
    L.append("-" * 70)
    ls = result["layer_scores"]
    L.append(f"Schicht-Scores:  SAST={sc(ls['SAST'])}   SCA={sc(ls['SCA'])}   IaC={sc(ls['IaC'])}")
    ts = result["total_score"]
    L.append(f"{'GESAMT-SCORE (SI)':<54}{ts:6.2f} / 100" if ts is not None
             else "GESAMT-SCORE: n/a")
    L.append("=" * 70)
    return "\n".join(L)


def _ask(p: str) -> str:
    """Fragt eine Eingabe interaktiv ab und gibt den eingegebenen Text getrimmt zurueck."""
    try:
        return input(p).strip()
    except EOFError:
        return ""


def prompt_languages(preset: Optional[str]) -> list[str]:
    """Ermittelt die zu scannenden Sprachen aus Flag oder Abfrage und normiert JavaScript auf TypeScript. Gibt die Sprachliste ohne Dubletten zurueck."""
    raw = preset or _ask("Welche Sprachen scannen? (z. B. python,typescript): ")
    langs: list[str] = []
    js_mapped = False
    for tok in raw.replace(";", ",").split(","):
        t = tok.strip().lower()
        if not t:
            continue
        if t in ("javascript", "js"):
            t = "typescript"
            js_mapped = True
        if t not in LANGUAGE_PROFILES:
            print(f"  Unbekannte Sprache '{t}' (bekannt: {', '.join(LANGUAGE_PROFILES)}).",
                  file=sys.stderr)
            continue
        if t not in langs:
            langs.append(t)
    if js_mapped:
        print("  Hinweis: 'javascript' wird als 'typescript' behandelt "
              "(TypeScript deckt .js/.jsx mit ab) - es wird keine separate "
              "JavaScript-Benchmark benoetigt.")
    return langs


def _ask_default(prompt: str, default: str) -> str:
    """Fragt einen Wert mit Standardvorgabe ab und liefert bei leerer Eingabe den Standard."""
    v = _ask(f"{prompt} [{default}]: ")
    return v or default


def _prompt_target() -> Path:
    """Fragt interaktiv nach dem Pfad des Ziel-Repos und prueft dessen Existenz."""
    while True:
        raw = _ask("Geben Sie den Pfad zum Ziel-Repository ein: ")
        if not raw:
            print("  Bitte einen Pfad angeben.", file=sys.stderr)
            continue
        p = Path(raw).expanduser()
        if p.exists():
            return p
        print(f"  Pfad '{p}' existiert nicht - bitte erneut.", file=sys.stderr)


def prompt_subdir(preset: Optional[str]) -> str:
    """Ermittelt einen optionalen Unterordner des Ziel-Repos aus Flag oder Abfrage."""
    raw = preset if preset is not None else \
        _ask("Unterordner scannen? (leer = ganzes Repo, z. B. backend): ")
    return raw.strip()


def prompt_exclude_dirs(preset: Optional[str]) -> list[str]:
    """Ermittelt die vom Scan auszuschliessenden Ordner-/Dateinamen aus Flag oder Abfrage."""
    raw = preset if preset is not None else \
        _ask("Ordner ausschliessen? (kommagetrennt, leer = keine, z. B. tests,docs): ")
    return [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]


def resolve_scan_root(target_path: Path, subdir: str) -> Path:
    """Loest die effektive Scan-Wurzel auf. Verhindert das Verlassen des Ziel-Repos
    (kein '..'-Ausbruch). Beendet das Programm bei ungueltigem Unterordner."""
    if not subdir:
        return target_path
    base = target_path.resolve()
    cand = (target_path / subdir).resolve()
    if cand != base and base not in cand.parents:
        print(f"Unterordner '{subdir}' liegt ausserhalb des Ziel-Repos. Abbruch.",
              file=sys.stderr)
        sys.exit(1)
    if not cand.exists():
        print(f"Unterordner '{cand}' existiert nicht. Abbruch.", file=sys.stderr)
        sys.exit(1)
    return cand


def prompt_compare_count(preset: Optional[int]) -> Optional[int]:
    """Anzahl der (populaersten) Referenz-Repos, gegen die das Ziel-Repo verglichen
    wird. None = alle vorhandenen."""
    if preset is not None:
        return preset if preset > 0 else None
    raw = _ask("Mit wie vielen der populaersten Referenz-Repos je Sprache vergleichen? "
               "(leer = alle): ").strip()
    if not raw:
        return None
    try:
        n = int(raw)
    except ValueError:
        print("  Ungueltige Zahl - es werden alle vorhandenen Referenz-Repos verwendet.",
              file=sys.stderr)
        return None
    return n if n > 0 else None


def main() -> None:
    """Einstiegspunkt: liest Parameter, stellt Benchmarks bereit und fuehrt je nach Modus Scoring oder einen reinen Scan aus."""
    ap = argparse.ArgumentParser(description="Dreischichtige sprachweise Sicherheitsbewertung. "
                                 "Nicht angegebene Parameter werden interaktiv abgefragt.")
    ap.add_argument("--target", type=Path, default=None, help="Pfad zum lokalen Ziel-Repo.")
    ap.add_argument("--languages", type=str, default=None, help="z. B. python,typescript")
    ap.add_argument("--repos", type=int, default=None,
                    help="Referenz-Repos je Sprache beim Neubau (Standard 100; "
                         "nicht-interaktiv, ueberspringt die j/n-Abfrage).")
    ap.add_argument("--compare-repos", type=int, default=None,
                    help="Mit wie vielen der populaersten Referenz-Repos je Sprache "
                         "verglichen wird (Standard: alle vorhandenen).")
    ap.add_argument("--token", type=str, default=None, help="GitHub-Token (sonst GITHUB_TOKEN).")
    ap.add_argument("--score-config", type=Path, default=None)
    ap.add_argument("--mode", choices=["score", "scan"], default=None,
                    help="score = Bewertung; scan = reiner Schwachstellenscan (Report).")
    ap.add_argument("--output", type=str, default=None,
                    help="Report-Ziel im scan-Modus ('-' = stdout; sonst Default reports/...).")
    ap.add_argument("--export-iac", action="store_true",
                    help="IaC-Daten aus vorhandenen Sprach-Benchmarks in benchmark_iac.json "
                         "exportieren und beenden (keine Scanner noetig).")
    ap.add_argument("--subdir", type=str, default=None,
                    help="Nur diesen Unterordner des Ziel-Repos scannen (z. B. backend).")
    ap.add_argument("--exclude-dirs", type=str, default=None,
                    help="Kommagetrennte Ordner-/Datei-Namen (glob), die vom Scan "
                         "ausgeschlossen werden (z. B. tests,docs,examples).")
    args = ap.parse_args()

    print("=" * 60)
    print("  Sprachweise, dreischichtige Sicherheitsbewertung")
    print("=" * 60)

    if args.export_iac:
        checked, added, total = export_iac_benchmark()
        print(f"\nIaC-Export: {checked} Repos mit IaC aus den Sprach-Benchmarks uebernommen "
              f"({added} neu) -> {total} Eintraege in {iac_benchmark_path()}.")
        if total == 0:
            print("  Hinweis: keine IaC-Daten gefunden. Existieren benchmark_<sprache>.json "
                  "mit Repos, die IaC-Artefakte (iac_loc>0) enthalten?")
        return

    missing = check_tools(("git", "semgrep", "trivy", "cloc"))
    if missing:
        print("Fehlende Tools im PATH: " + ", ".join(missing) +
              "\nInstallation (macOS): brew install " +
              " ".join(m for m in missing if m != "git"), file=sys.stderr)
        sys.exit(1)

    score_cfg = json.loads(args.score_config.read_text()) if args.score_config else {}
    cfg = config_from_dict(score_cfg)
    exclude = re.compile(cfg.exclude_path_regex) if cfg.exclude_path_regex else None
    tools = Toolchain(semgrep_config=score_cfg.get("semgrep_config", "p/default"),
                      trivy_skip_db_update=score_cfg.get("trivy_skip_db_update", False))

    mode = prompt_mode(args.mode)

    target_path = args.target or _prompt_target()
    if not target_path.exists():
        print(f"Pfad '{target_path}' existiert nicht. Abbruch.", file=sys.stderr)
        sys.exit(1)

    subdir = prompt_subdir(args.subdir)
    exclude_dirs = prompt_exclude_dirs(args.exclude_dirs)
    scan_root = resolve_scan_root(target_path, subdir)
    if subdir or exclude_dirs:
        info = []
        if subdir:
            info.append(f"Unterordner '{subdir}'")
        if exclude_dirs:
            info.append("ausgeschlossen: " + ", ".join(exclude_dirs))
        print("  Scan-Umfang: " + " | ".join(info))

    if mode == "scan":
        print(f"\nFuehre Schwachstellenscan auf {scan_root} durch (Semgrep + Trivy) ...")
        try:
            report = run_scan_only(scan_root, tools, cfg, exclude, extra_ignore=exclude_dirs)
        except subprocess.CalledProcessError as e:
            cmd = " ".join(e.cmd) if isinstance(e.cmd, list) else str(e.cmd)
            print(f"\nFehler beim Scannen (Exit {e.returncode}).\n  Kommando: {cmd}",
                  file=sys.stderr)
            if getattr(e, "stderr", None):
                print("  Scanner-Ausgabe:\n    " + str(e.stderr).replace("\n", "\n    "),
                      file=sys.stderr)
            sys.exit(1)
        out_path = write_report(report, args.output, scan_root)
        print_scan_summary(report, out_path)
        return

    languages = prompt_languages(args.languages)
    if not languages:
        print("Keine gueltige Sprache gewaehlt. Abbruch.", file=sys.stderr)
        sys.exit(1)

    compare_count = prompt_compare_count(args.compare_repos)

    token = args.token or os.environ.get("GITHUB_TOKEN")

    def resolve_token() -> Optional[str]:
        """Liefert das GitHub-Token und fragt es bei Bedarf interaktiv (verdeckt) ab."""
        nonlocal token
        if not token:
            print("  Es wird ein GitHub-Token benoetigt, um eine Referenz-Datenbank zu erstellen.")
            try:
                import getpass
                token = getpass.getpass("  GitHub-Token eingeben (Eingabe nicht sichtbar): ").strip()
            except Exception:
                token = _ask("  GitHub-Token eingeben: ")
        return token

    gh: Optional[GitHubClient] = None

    benchmarks: dict[str, list[dict]] = {}
    for lang in languages:
        if benchmark_exists(lang):
            benchmarks[lang] = load_benchmark(lang)
            print(f"[{lang}] vorhandene Referenz-Datenbank geladen "
                  f"({len(benchmarks[lang])} Repos).")
            continue

        print(f"[{lang}] Es existiert keine Referenz-Datenbank.")
        if args.repos is not None:
            do_build, count = True, args.repos
        else:
            do_build = _ask(f"  Soll fuer '{lang}' eine erstellt werden? (j/n): ").lower() \
                in ("j", "ja", "y", "yes")
            count = 0
            if do_build:
                resolve_token()
                count = DEFAULT_BENCHMARK_REPOS
                print(f"  ! Hinweis: Es werden die Top {count} populaersten Repos geklont "
                      f"und gescannt - das kann SEHR lange dauern (mit --repos aenderbar).")

        if do_build and count > 0:
            if gh is None:
                gh = GitHubClient(token=resolve_token() or None)
            benchmarks[lang] = build_language_benchmark(lang, count, gh, tools, cfg, exclude)
        else:
            print(f"[{lang}] ohne Referenz-Datenbank - wird im Score uebersprungen.")
            benchmarks[lang] = []

    if compare_count is not None:
        for lang in list(benchmarks):
            full = len(benchmarks[lang])
            ranked = sorted(benchmarks[lang], key=_repo_stars, reverse=True)
            benchmarks[lang] = ranked[:compare_count]
            if full:
                used = len(benchmarks[lang])
                hinweis = "" if used == full else f" (von {full} vorhandenen)"
                print(f"[{lang}] Vergleich gegen Top {used}{hinweis} Referenz-Repos.")

    print(f"\nScanne Ziel-Repo {scan_root} ...")
    try:
        target = scan_target(scan_root, languages, tools, cfg, exclude,
                             extra_ignore=exclude_dirs)
    except subprocess.CalledProcessError as e:
        cmd = " ".join(e.cmd) if isinstance(e.cmd, list) else str(e.cmd)
        print(f"\nFehler beim Scannen des Ziel-Repos (Exit {e.returncode}).", file=sys.stderr)
        print(f"  Kommando: {cmd}", file=sys.stderr)
        detail = getattr(e, "stderr", None)
        if detail:
            print("  Scanner-Ausgabe:\n    " + str(detail).replace("\n", "\n    "), file=sys.stderr)
        sys.exit(1)
    iac_benchmark = load_iac_benchmark() or None
    if iac_benchmark:
        print(f"[iac] separate IaC-Benchmark geladen ({len(iac_benchmark)} Repos).")
    result = run_assessment(languages, target, benchmarks, cfg, "loc",
                            iac_benchmark=iac_benchmark)
    secrets = target.get("secrets", {"total": 0, "items": []})
    score_report = {
        "tool": "secscore-score",
        "mode": "scoring",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "target": str(scan_root),
        "languages": languages,
        "compare_repos": compare_count,
        "scope": {"scan_root": str(scan_root), "excluded_dirs": exclude_dirs},
        "result": result,
        "secrets": secrets,
    }
    if args.output != "-":
        print("\n" + format_report(result))
        notice = format_secrets_notice(secrets)
        if notice:
            print(notice)
    out_path = write_report(score_report, args.output, scan_root, prefix="score")
    if out_path:
        print(f"\nScore-Report (JSON) gespeichert: {out_path}")


if __name__ == "__main__":
    main()