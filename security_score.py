#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import date, datetime
from pathlib import Path
from typing import Optional

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
LAYERS = ["SAST", "SCA", "IaC"]


def _json_default(value):
    """Ersatzwert fuer Objekte, die json nicht direkt serialisieren kann. Gibt schlicht den Text 'inf' zurueck."""
    return "inf"


class Config:
    """Konfiguration des Scorings: Severity-Gewichte, Schicht-Gewichte, Severity-Mappings und Ausschlussmuster."""

    def __init__(self):
        """Legt eine Config mit Standardwerten an. Die enthaltenen Dictionaries werden bei jeder Instanz neu erzeugt."""
        self.severity_weights = {"CRITICAL": 9.5, "HIGH": 7.95, "MEDIUM": 5.45, "LOW": 2.0}
        self.layer_weights = {"SAST": 1 / 3, "SCA": 1 / 3, "IaC": 1 / 3}
        self.semgrep_severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        self.trivy_severity_map = {
            "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
            "LOW": "LOW", "UNKNOWN": "LOW",
        }
        self.include_secrets = False
        self.cve_cutoff = None
        self.exclude_path_regex = r"(^|/)(tests?|__tests__|mocks?|fixtures?|e2e)(/|$)"


def config_from_dict(d: dict) -> "Config":
    """Erzeugt eine Config aus einem Dict, uebernimmt bekannte Felder und normiert die Schicht-Gewichte auf Summe 1."""
    base = Config()
    for key, value in d.items():
        if hasattr(base, key):
            setattr(base, key, value)
    total = sum(base.layer_weights.values())
    if total > 0:
        base.layer_weights = {k: v / total for k, v in base.layer_weights.items()}
    return base


def normalize_severity(raw: Optional[str], mapping: dict[str, str]) -> Optional[str]:
    """Bildet einen rohen Scanner-Schweregrad auf eine kanonische Klasse (CRITICAL/HIGH/MEDIUM/LOW) ab."""
    if raw is None:
        return None
    key = str(raw).strip().upper()
    if key in SEVERITIES:
        return key
    return mapping.get(key)


def _excluded(path: Optional[str], pattern: Optional[re.Pattern]) -> bool:
    """Prueft, ob ein Pfad dem konfigurierten Ausschlussmuster entspricht."""
    if pattern is None or not path:
        return False
    return pattern.search(path) is not None


def parse_semgrep(path: Path, cfg: Config, exclude: Optional[re.Pattern]) -> dict[str, int]:
    """Semgrep == SAST. Gibt Severity-Zaehlungen {CRITICAL:.., HIGH:.., ...}."""
    counts = {s: 0 for s in SEVERITIES}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for res in data.get("results", []):
        fpath = res.get("path")
        if _excluded(fpath, exclude):
            continue
        raw = res.get("extra", {}).get("severity")
        sev = normalize_severity(raw, cfg.semgrep_severity_map)
        if sev:
            counts[sev] += 1
    return counts


def _after_cutoff(vuln: dict, cutoff: Optional[date]) -> bool:
    """Prueft, ob eine Schwachstelle hinter einem optionalen Veroeffentlichungs-Stichtag liegt. Ohne Stichtag immer False."""
    if cutoff is None:
        return False
    raw = vuln.get("PublishedDate") or vuln.get("LastModifiedDate")
    if not raw:
        return False
    try:
        d = datetime.fromisoformat(str(raw).replace("Z", "+00:00")).date()
    except ValueError:
        return False
    return d > cutoff


def parse_trivy(path: Path, cfg: Config, exclude: Optional[re.Pattern]) -> dict[str, dict[str, int]]:
    """Trivy -> SCA (Vulnerabilities), IaC (Misconfigurations), optional Secrets.

    Gibt {'SCA': {sev:count}, 'IaC': {sev:count}} (Secrets nur falls aktiviert).
    """
    out = {"SCA": {s: 0 for s in SEVERITIES}, "IaC": {s: 0 for s in SEVERITIES}}
    if cfg.include_secrets:
        out["Secrets"] = {s: 0 for s in SEVERITIES}

    cutoff = date.fromisoformat(cfg.cve_cutoff) if cfg.cve_cutoff else None
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    for r in data.get("Results", []):
        target = r.get("Target")
        if _excluded(target, exclude):
            continue

        for v in r.get("Vulnerabilities", []) or []:
            if _after_cutoff(v, cutoff):
                continue
            sev = normalize_severity(v.get("Severity"), cfg.trivy_severity_map)
            if sev:
                out["SCA"][sev] += 1

        for m in r.get("Misconfigurations", []) or []:
            sev = normalize_severity(m.get("Severity"), cfg.trivy_severity_map)
            if sev:
                out["IaC"][sev] += 1

        if cfg.include_secrets:
            for _ in r.get("Secrets", []) or []:
                out["Secrets"]["HIGH"] += 1

    return out


DEFAULT_IAC_LANGUAGES = {"Dockerfile", "YAML", "yaml", "Docker", "HCL", "Terraform"}


def resolve_exposure(exposure: dict) -> dict[str, float]:
    """Liefert {'SAST': code_kloc, 'SCA': n_deps, 'IaC': iac_kloc}.

    Zwei Eingabeformen:
      1) explizit: {"code_kloc": .., "iac_kloc": .., "dependencies": ..}
      2) Sprach-Aufschluesselung:
         {"loc_by_language": {"Python": 8200, "JavaScript": 4200,
                               "Dockerfile": 30, "YAML": 110},
          "iac_languages": ["Dockerfile", "YAML"],
          "exclude_languages": ["Markdown"],
          "dependencies": 57}
         -> code_kloc = Summe der Quellsprachen (ohne IaC/exclude) / 1000
            iac_kloc  = Summe der IaC-Sprachen / 1000
    """
    n_deps = float(exposure.get("dependencies", 0))

    if "loc_by_language" in exposure:
        loc = exposure["loc_by_language"]
        iac_langs = set(exposure.get("iac_languages", DEFAULT_IAC_LANGUAGES))
        excl = set(exposure.get("exclude_languages", []))
        code_loc = sum(v for k, v in loc.items() if k not in iac_langs and k not in excl)
        iac_loc = sum(v for k, v in loc.items() if k in iac_langs and k not in excl)
        return {"SAST": code_loc / 1000.0, "SCA": n_deps, "IaC": iac_loc / 1000.0}

    return {
        "SAST": float(exposure.get("code_kloc", 0.0)),
        "SCA": n_deps,
        "IaC": float(exposure.get("iac_kloc", 0.0)),
    }


def weighted_count(sev_counts: dict[str, int], weights: dict[str, float]) -> float:
    """Schritt 1: G = sum_k w_k * n_k."""
    return sum(weights.get(s, 0.0) * sev_counts.get(s, 0) for s in SEVERITIES)


def density(g: float, e: float) -> float:
    """Schritt 2: VD = G / E. Definiert 0/0 = 0 (Bestfall), G>0 / 0 = inf."""
    if e == 0:
        return 0.0 if g == 0 else float("inf")
    return g / e


def strict_cdf(value: float, population: list[float]) -> float:
    """Anteil der Population strikt < value (empirische Verteilungsfunktion)."""
    if not population:
        return 0.0
    less = sum(1 for x in population if x < value)
    return less / len(population)


def layer_score(vd: float, benchmark_vds: list[float]) -> Optional[float]:
    """Schritt 3: S = 100 * (1 - F(VD)). None, falls kein Benchmark vorhanden."""
    if not benchmark_vds:
        return None
    return 100.0 * (1.0 - strict_cdf(vd, benchmark_vds))


def security_index(layer_scores: dict[str, Optional[float]], weights: dict[str, float]) -> Optional[float]:
    """Schritt 4: SI = sum_L alpha_L * S_L (nur ueber Schichten mit Score)."""
    num, wsum = 0.0, 0.0
    for L in LAYERS:
        s = layer_scores.get(L)
        if s is None:
            continue
        a = weights.get(L, 0.0)
        num += a * s
        wsum += a
    if wsum == 0:
        return None
    return num / wsum


class RepoResult:
    """Ergebnisstruktur eines vermessenen Repositories mit seinen Dichten je Schicht."""

    def __init__(self, name, counts, exposure, densities):
        """Speichert Name, Roh-Zaehlwerte, Bezugsgroessen und die berechneten Dichten eines Repos."""
        self.name = name
        self.counts = counts
        self.exposure = exposure
        self.densities = densities


def process_repo(repo_cfg: dict, cfg: Config, exclude: Optional[re.Pattern]) -> RepoResult:
    """Wandelt eine Repo-Konfiguration bzw. deren Scanner-Funde in ein RepoResult mit Dichten je Schicht um."""
    if "densities" in repo_cfg:
        dens = {L: float(repo_cfg["densities"].get(L, 0.0)) for L in LAYERS}
        return RepoResult(
            name=repo_cfg.get("name", "unnamed"),
            counts=repo_cfg.get("counts", {L: {s: 0 for s in SEVERITIES} for L in LAYERS}),
            exposure=repo_cfg.get("exposure_resolved", {L: 0.0 for L in LAYERS}),
            densities=dens,
        )

    counts: dict[str, dict[str, int]] = {L: {s: 0 for s in SEVERITIES} for L in LAYERS}

    if repo_cfg.get("semgrep"):
        counts["SAST"] = parse_semgrep(Path(repo_cfg["semgrep"]), cfg, exclude)
    if repo_cfg.get("trivy"):
        trivy = parse_trivy(Path(repo_cfg["trivy"]), cfg, exclude)
        counts["SCA"] = trivy["SCA"]
        counts["IaC"] = trivy["IaC"]

    exposure = resolve_exposure(repo_cfg.get("exposure", {}))
    densities = {
        L: density(weighted_count(counts[L], cfg.severity_weights), exposure[L])
        for L in LAYERS
    }
    return RepoResult(repo_cfg.get("name", "unnamed"), counts, exposure, densities)


def _resolve_benchmark_entries(config_dict: dict) -> list[dict]:
    """Sammelt Benchmark-Repos aus inline 'benchmark' und/oder einer
    'benchmark_db'-Datei und filtert optional nach 'benchmark_component'.

    Damit lassen sich sprach-/schichtgetrennte Benchmarks realisieren: pro
    Ziel-Bereich (z. B. Python-Backend) wird gegen die gleichnamige Komponente
    der Benchmark-DB bewertet.
    """
    entries: list[dict] = list(config_dict.get("benchmark", []))
    db_path = config_dict.get("benchmark_db")
    if db_path:
        db = json.loads(Path(db_path).read_text(encoding="utf-8"))
        entries.extend(db.get("repos", []))
    component = config_dict.get("benchmark_component")
    if component:
        entries = [e for e in entries if e.get("component") == component]
    return entries


def run(config_dict: dict) -> dict:
    """Fuehrt das Scoring eines Ziels gegen die aufgeloeste Benchmark aus und liefert das Ergebnis-Dict."""
    cfg = config_from_dict(config_dict)
    exclude = re.compile(cfg.exclude_path_regex) if cfg.exclude_path_regex else None

    entries = _resolve_benchmark_entries(config_dict)
    benchmark = [process_repo(rc, cfg, exclude) for rc in entries]
    benchmark_vds = {L: [b.densities[L] for b in benchmark] for L in LAYERS}

    target = process_repo(config_dict["target"], cfg, exclude)
    scores = {L: layer_score(target.densities[L], benchmark_vds[L]) for L in LAYERS}
    si = security_index(scores, cfg.layer_weights)

    warnings = []
    for L in LAYERS:
        total = sum(target.counts[L].values())
        if total == 0:
            warnings.append(
                f"{L}: 0 Funde - moegliches Artefakt (z. B. nicht aufgeloeste "
                f"Abhaengigkeiten); Score {scores[L]} ist mit Vorsicht zu lesen."
            )

    return {
        "target": target,
        "benchmark": benchmark,
        "benchmark_vds": benchmark_vds,
        "layer_scores": scores,
        "security_index": si,
        "warnings": warnings,
        "config": cfg,
    }


def format_report(result: dict) -> str:
    """Formatiert das Score-Ergebnis als lesbaren Text."""
    t: RepoResult = result["target"]
    lines = []
    lines.append("=" * 64)
    lines.append(f"  SICHERHEITS-SCORE  |  Ziel-Repo: {t.name}")
    lines.append("=" * 64)
    lines.append(f"{'Schicht':<6} {'C':>3} {'H':>3} {'M':>3} {'L':>3} {'Exposition':>12} "
                 f"{'Dichte':>10} {'Score':>8}")
    lines.append("-" * 64)
    for L in LAYERS:
        c = t.counts[L]
        vd = t.densities[L]
        sc = result["layer_scores"][L]
        vd_str = "inf" if vd == float("inf") else f"{vd:.4f}"
        sc_str = "  n/a" if sc is None else f"{sc:6.2f}"
        lines.append(
            f"{L:<6} {c['CRITICAL']:>3} {c['HIGH']:>3} {c['MEDIUM']:>3} {c['LOW']:>3} "
            f"{t.exposure[L]:>12.3f} {vd_str:>10} {sc_str:>8}"
        )
    lines.append("-" * 64)
    si = result["security_index"]
    lines.append(f"{'FINALER SECURITY INDEX (SI)':<46}{'':>9}{si:6.2f} / 100"
                 if si is not None else "FINALER SECURITY INDEX: n/a")
    lines.append("=" * 64)
    if result["warnings"]:
        lines.append("Hinweise:")
        for w in result["warnings"]:
            lines.append(f"  ! {w}")
    return "\n".join(lines)


def main() -> None:
    """Einstiegspunkt des eigenstaendigen Scorers: liest die Konfiguration und gibt das Ergebnis aus."""
    ap = argparse.ArgumentParser(description="Berechnung des Sicherheits-Scores (SI).")
    ap.add_argument("config", type=Path, help="Pfad zur Konfigurations-JSON.")
    ap.add_argument("--json", action="store_true", help="Ergebnis als JSON ausgeben.")
    args = ap.parse_args()

    config_dict = json.loads(args.config.read_text(encoding="utf-8"))
    result = run(config_dict)

    if args.json:
        out = {
            "target": result["target"].name,
            "densities": result["target"].densities,
            "layer_scores": result["layer_scores"],
            "security_index": result["security_index"],
            "warnings": result["warnings"],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False, default=_json_default))
    else:
        print(format_report(result))


if __name__ == "__main__":
    main()