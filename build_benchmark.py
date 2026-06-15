#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from security_score import (
    LAYERS, SEVERITIES, Config, config_from_dict, density, parse_semgrep, parse_trivy,
    resolve_exposure, weighted_count,
)

GITHUB_API = "https://api.github.com"


def _json_default(value):
    """Ersatzwert fuer Objekte, die json nicht direkt serialisieren kann. Gibt schlicht den Text 'inf' zurueck."""
    return "inf"


def _default_ssl_context() -> "ssl.SSLContext":
    """SSL-Kontext mit certifi-CA-Bundle, falls verfuegbar (loest das
    macOS-Problem 'CERTIFICATE_VERIFY_FAILED' bei python.org-Builds). Faellt
    sonst auf den Standardkontext zurueck."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


class GitHubClient:
    """Schlanker GitHub-REST-Client zum Suchen und Klonen von Repositories. Beachtet das Rate-Limit der Such-API."""

    def __init__(self, token=None, timeout=30, ssl_context=None):
        """Initialisiert den Client mit optionalem Token und Zeitlimit. Ohne SSL-Kontext wird ein Standardkontext (mit certifi) erzeugt."""
        self.token = token
        self.timeout = timeout
        if ssl_context is None:
            ssl_context = _default_ssl_context()
        self.ssl_context = ssl_context

    def _headers(self) -> dict[str, str]:
        """Liefert die HTTP-Header inklusive Authentifizierung fuer GitHub-Anfragen."""
        h = {"Accept": "application/vnd.github+json", "User-Agent": "secscore-benchmark"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _get(self, url: str) -> tuple[dict, dict]:
        """Fuehrt eine GET-Anfrage gegen die GitHub-API aus und gibt die JSON-Antwort zurueck."""
        req = urllib.request.Request(url, headers=self._headers())
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data, dict(resp.headers)

    def _respect_rate_limit(self, headers: dict) -> None:
        """Pausiert bei erreichtem Such-Rate-Limit bis zum Reset-Zeitpunkt."""
        remaining = headers.get("X-RateLimit-Remaining")
        reset = headers.get("X-RateLimit-Reset")
        if remaining is not None and reset is not None and int(remaining) == 0:
            wait = max(0, int(reset) - int(time.time())) + 2
            print(f"  [rate-limit] warte {wait}s ...", file=sys.stderr)
            time.sleep(wait)

    def search_repositories(self, query: str, count: int) -> list[dict]:
        """Top-Repos nach Sternen. Liefert [{full_name, clone_url, stars}]."""
        results: list[dict] = []
        page = 1
        per_page = min(100, count)
        while len(results) < count and page <= 10:
            url = (f"{GITHUB_API}/search/repositories?q={urllib.parse.quote(query)}"
                   f"&sort=stars&order=desc&per_page={per_page}&page={page}")
            data, headers = self._get(url)
            items = data.get("items", [])
            if not items:
                break
            for it in items:
                results.append({
                    "full_name": it["full_name"],
                    "clone_url": it["clone_url"],
                    "stars": it.get("stargazers_count", 0),
                })
                if len(results) >= count:
                    break
            self._respect_rate_limit(headers)
            page += 1
        return results[:count]


class Toolchain:
    """Kapselt die externen Analysewerkzeuge (Semgrep, Trivy, cloc) mit fester Konfiguration. Stellt je Werkzeug eine Ausfuehrungsmethode bereit."""

    def __init__(self, semgrep_config="p/default", timeout=1800, max_memory_mb=4000,
                 metrics="off", trivy_skip_db_update=False):
        """Initialisiert die Werkzeugkette mit Semgrep-Regelwerk, Zeit- und Speicherlimit sowie Trivy-Optionen."""
        self.semgrep_config = semgrep_config
        self.timeout = timeout
        self.max_memory_mb = max_memory_mb
        self.metrics = metrics
        self.trivy_skip_db_update = trivy_skip_db_update

    def _run(self, cmd, ok_codes=(0,), timeout=1800):
        """Fuehrt cmd aus, faengt stdout/stderr ab und macht Fehler sichtbar. Akzeptiert mehrere gueltige Exit-Codes (Semgrep: 0 und 1)."""
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode not in ok_codes:
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-6:]
            raise subprocess.CalledProcessError(
                proc.returncode, cmd, output=proc.stdout,
                stderr="\n".join(tail) or "(keine Fehlerausgabe)")
        return proc

    def clone(self, clone_url: str, dest: Path) -> None:
        """Klont ein Repository flach in das Zielverzeichnis."""
        self._run(["git", "clone", "--depth", "1", "--quiet", clone_url, str(dest)],
                  timeout=self.timeout)

    def semgrep(self, repo: Path, out: Path) -> None:
        """Fuehrt Semgrep auf einem Verzeichnis aus und schreibt die JSON-Ausgabe."""
        self._run(["semgrep", "scan", "--config", self.semgrep_config,
                   "--metrics", self.metrics, "--max-memory", str(self.max_memory_mb),
                   "--json", "--output", str(out), str(repo)],
                  ok_codes=(0, 1), timeout=self.timeout)

    def trivy(self, repo: Path, out: Path) -> None:
        """Fuehrt Trivy (Schwachstellen, Fehlkonfigurationen, Secrets) auf einem Verzeichnis aus und schreibt die JSON-Ausgabe."""
        cmd = ["trivy", "fs", "--quiet", "--format", "json",
               "--scanners", "vuln,misconfig,secret"]
        if self.trivy_skip_db_update:
            cmd.append("--skip-db-update")
        cmd += ["--output", str(out), str(repo)]
        self._run(cmd, ok_codes=(0,), timeout=self.timeout)

    def cloc(self, repo: Path) -> dict:
        """Fuehrt cloc auf einem Verzeichnis aus und gibt die JSON-Ausgabe als Dict zurueck."""
        proc = self._run(["cloc", "--json", str(repo)], ok_codes=(0,), timeout=self.timeout)
        return json.loads(proc.stdout) if proc.stdout.strip() else {}


def cloc_to_loc_by_language(cloc_json: dict) -> dict[str, int]:
    """Wandelt die cloc-JSON-Ausgabe in ein Mapping Sprache -> Codezeilen um."""
    return {lang: info.get("code", 0)
            for lang, info in cloc_json.items()
            if lang not in ("header", "SUM") and isinstance(info, dict)}


def count_dependencies(repo: Path) -> int:
    """Zaehlt aufgeloeste Abhaengigkeiten. Lockfiles werden bevorzugt (inkl.
    transitiver), Manifeste sind der Fallback (nur direkte).

    Diese Funktion ist bewusst konservativ und gut dokumentiert, weil der
    SCA-Nenner methodisch sensibel ist. Fuer maximale Konsistenz mit den
    (auch transitiven) Trivy-Funden empfiehlt sich der Lockfile-Pfad.
    """
    total = 0
    for lock in repo.rglob("package-lock.json"):
        try:
            d = json.loads(lock.read_text(encoding="utf-8"))
            pkgs = d.get("packages")
            if isinstance(pkgs, dict):
                total += sum(1 for k in pkgs if k)
            else:
                total += len(d.get("dependencies", {}))
        except Exception:
            pass
    for lock in repo.rglob("poetry.lock"):
        try:
            total += lock.read_text(encoding="utf-8").count("[[package]]")
        except Exception:
            pass
    if total > 0:
        return total
    for req in repo.rglob("requirements*.txt"):
        try:
            for line in req.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s and not s.startswith("#") and not s.startswith("-"):
                    total += 1
        except Exception:
            pass
    for pj in repo.rglob("package.json"):
        if "node_modules" in str(pj):
            continue
        try:
            d = json.loads(pj.read_text(encoding="utf-8"))
            total += len(d.get("dependencies", {})) + len(d.get("devDependencies", {}))
        except Exception:
            pass
    return total


def analyze_repo(repo: Path, cfg: Config, tools: Toolchain, exclude) -> dict:
    """Scannt ein geklontes Repo mit Semgrep, Trivy und cloc und berechnet die Schicht-Kennzahlen. Gibt ein Dict mit Zaehlwerten, LoC und Dichten zurueck."""
    sem_out = repo / "_semgrep.json"
    tri_out = repo / "_trivy.json"
    tools.semgrep(repo, sem_out)
    tools.trivy(repo, tri_out)

    counts = {L: {s: 0 for s in SEVERITIES} for L in LAYERS}
    counts["SAST"] = parse_semgrep(sem_out, cfg, exclude)
    trivy = parse_trivy(tri_out, cfg, exclude)
    counts["SCA"], counts["IaC"] = trivy["SCA"], trivy["IaC"]

    loc = cloc_to_loc_by_language(tools.cloc(repo))
    exposure_cfg = {
        "loc_by_language": loc,
        "iac_languages": list(cfg.__dict__.get("iac_languages", []))
                         or ["Dockerfile", "YAML", "yaml"],
        "dependencies": count_dependencies(repo),
    }
    exposure = resolve_exposure(exposure_cfg)
    densities = {L: density(weighted_count(counts[L], cfg.severity_weights), exposure[L])
                 for L in LAYERS}
    return {"counts": counts, "exposure_resolved": exposure, "densities": densities}


class BuildConfig:
    """Konfiguration fuer den Benchmark-Bau (Komponenten, Anzahl Repos, Score- und Werkzeug-Einstellungen)."""

    def __init__(self, components=None, output="benchmark_db.json",
                 score_config=None, limit_override=None):
        """Initialisiert die Bau-Konfiguration. Listen/Dictionaries werden bei None neu angelegt."""
        self.components = components if components is not None else []
        self.output = output
        self.score_config = score_config if score_config is not None else {}
        self.limit_override = limit_override


def build(bcfg: BuildConfig, gh: GitHubClient, tools: Toolchain,
          analyze: Callable = analyze_repo) -> dict:
    """Baut die Benchmark fuer alle konfigurierten Komponenten: Repos suchen, klonen, vermessen. Gibt die gesammelte Referenzdatenbank zurueck."""
    cfg = config_from_dict(bcfg.score_config)
    import re
    exclude = re.compile(cfg.exclude_path_regex) if cfg.exclude_path_regex else None

    db: list[dict] = []
    for comp in bcfg.components:
        count = bcfg.limit_override or comp.get("count", 10)
        print(f"[Komponente] {comp['name']}  (Query: {comp['query']}, n={count})")
        repos = gh.search_repositories(comp["query"], count)
        for i, r in enumerate(repos, 1):
            name = r["full_name"]
            workdir = Path(tempfile.mkdtemp(prefix="benchrepo_"))
            target = workdir / "repo"
            try:
                print(f"  ({i}/{len(repos)}) {name}  [*{r['stars']}] klonen ...")
                tools.clone(r["clone_url"], target)
                metrics = analyze(target, cfg, tools, exclude)
                db.append({
                    "name": name,
                    "component": comp["name"],
                    "stars": r["stars"],
                    "densities": metrics["densities"],
                    "counts": metrics["counts"],
                    "exposure_resolved": metrics["exposure_resolved"],
                })
                print(f"      dichten: " + ", ".join(
                    f"{L}={metrics['densities'][L]:.4f}" for L in LAYERS))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                    urllib.error.URLError, FileNotFoundError, KeyError) as e:
                detail = getattr(e, "stderr", None)
                msg = f"{type(e).__name__}: {e}"
                if detail:
                    msg += f"\n      -> {detail}"
                print(f"      uebersprungen ({msg})", file=sys.stderr)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)

    out = {"benchmark_size": len(db), "repos": db}
    Path(bcfg.output).write_text(json.dumps(out, indent=2, ensure_ascii=False,
                                            default=_json_default), encoding="utf-8")
    print(f"\n{len(db)} Repos in '{bcfg.output}' gespeichert.")
    return out


def check_tools(required=("git", "semgrep", "trivy", "cloc")) -> list[str]:
    """Prueft, ob die externen Tools im PATH liegen. Gibt fehlende zurueck."""
    return [t for t in required if shutil.which(t) is None]


def main() -> None:
    """Einstiegspunkt des Benchmark-Builders: liest die Konfiguration und erzeugt die Benchmark-Datei."""
    ap = argparse.ArgumentParser(description="Benchmark-Datenbasis automatisch erstellen.")
    ap.add_argument("config", type=Path, help="Build-Konfigurations-JSON.")
    ap.add_argument("--limit", type=int, default=None,
                    help="Anzahl Repos je Komponente (ueberschreibt 'count').")
    ap.add_argument("--output", type=str, default=None, help="Ausgabedatei.")
    ap.add_argument("--token", type=str, default=None, help="GitHub-Token (sonst GITHUB_TOKEN).")
    args = ap.parse_args()

    raw = json.loads(args.config.read_text(encoding="utf-8"))

    missing = check_tools()
    if missing:
        print("Fehlende Tools im PATH: " + ", ".join(missing), file=sys.stderr)
        print("Installation (macOS): brew install " +
              " ".join(m for m in missing if m != "git"), file=sys.stderr)
        sys.exit(1)

    bcfg = BuildConfig(
        components=raw.get("components", []),
        output=args.output or raw.get("output", "benchmark_db.json"),
        score_config=raw.get("score_config", {}),
        limit_override=args.limit,
    )
    token = args.token or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Warnung: kein GitHub-Token (GITHUB_TOKEN) gesetzt - API-Limit ist niedrig.",
              file=sys.stderr)

    gh = GitHubClient(token=token)
    tools = Toolchain(semgrep_config=raw.get("semgrep_config", "auto"))
    build(bcfg, gh, tools)


if __name__ == "__main__":
    main()