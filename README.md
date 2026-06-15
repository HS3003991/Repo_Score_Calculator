# secscore

Containerisiertes Werkzeug zur Sicherheitsbewertung von Quellcode-Repositories.
Es scannt ein Repo mit Semgrep (SAST), Trivy (SCA, IaC-Fehlkonfigurationen,
Secrets) und cloc (Codezeilen) und bietet zwei Betriebsarten:

- Scoring: ein benchmark-relativer, dreischichtiger Sicherheitsscore (SAST/SCA/IaC).
  Das Ziel-Repo wird gegen eine Referenzverteilung populaerer Repositories verglichen;
  Ergebnis ist ein Wert von 0–100 je Schicht und gesamt. Die Bewertung wird als
  Tabelle ausgegeben und zusaetzlich als JSON-Report gespeichert.
- Scan: ein reiner, kombinierter Schwachstellen-Report (JSON) ohne Scoring,
  in dem Semgrep- und Trivy-Funde zusammengefuehrt sind.

Alle Werkzeuge sind im Image fest installiert (reproduzierbar gepinnte Versionen:
Trivy 0.70.0, Semgrep 1.157.0).

## Image bauen

```bash
docker build -t secscore .
```

## Start (interaktiv)

Beim Start fragt das Tool gefuehrt nach Modus, Ziel-Repo, Sprachen usw. Das Ziel-Repo
wird read-only (`:ro`) hineingereicht, der `benchmarks`-Ordner fuer die Referenzdaten:

```bash
docker run -it --rm \
  -v "$(pwd)/benchmarks:/app/benchmarks" \
  -v "/pfad/zum/repo:/target:ro" \
  secscore
```

Alles nach dem Image-Namen wird an das Tool durchgereicht – Parameter lassen sich also
auch als Flags angeben (siehe unten), dann entfaellt die jeweilige Abfrage.

## Volumes

| Mount | Zweck |
|-------|-------|
| `-v "$(pwd)/benchmarks:/app/benchmarks"` | Referenz-Benchmarks (werden gelesen/geschrieben, bleiben erhalten) |
| `-v "$(pwd)/reports:/app/reports"` | Ablage der Scan-Reports auf dem Host |
| `-v "/pfad/zum/repo:/target:ro"` | das zu scannende Ziel-Repo (read-only) |
| `-e GITHUB_TOKEN=...` | nur noetig, wenn eine Benchmark neu gebaut wird |

## Beispiele

**Scoring, gefuehrt:**
```bash
docker run -it --rm \
  -v "$(pwd)/benchmarks:/app/benchmarks" \
  -v "/pfad/zum/repo:/target:ro" \
  secscore --mode score --target /target
```

**Scoring, nicht-interaktiv (Sprachen, Gewichtung, Vergleichsumfang):**
```bash
docker run --rm \
  -v "$(pwd)/benchmarks:/app/benchmarks" \
  -v "/pfad/zum/repo:/target:ro" \
  secscore --mode score --target /target \
           --languages python,typescript --compare-repos 50
```
Die Bewertung erscheint als Tabelle in der Konsole; der vollstaendige Score (alle
Schicht- und Gesamtwerte) wird zugleich als JSON gespeichert. Standardziel ist
`reports/score-<repo>-<zeitstempel>.json`, per `--output` aenderbar (auch `-` fuer
stdout). Dafuer wie beim Scan einen reports-Ordner mounten:
```bash
docker run --rm \
  -v "$(pwd)/benchmarks:/app/benchmarks" \
  -v "$(pwd)/reports:/app/reports" \
  -v "/pfad/zum/repo:/target:ro" \
  secscore --mode score --target /target --languages python --output /app/reports/score.json
```

**Benchmark bei Bedarf neu bauen (braucht Token):**
```bash
docker run -it --rm \
  -e GITHUB_TOKEN=ghp_xxx \
  -v "$(pwd)/benchmarks:/app/benchmarks" \
  -v "/pfad/zum/repo:/target:ro" \
  secscore --mode score --target /target --languages python --repos 100
```

**Reiner Scan und Report lokal sichern** (Report landet in `./reports/`):
```bash
docker run --rm \
  -v "$(pwd)/reports:/app/reports" \
  -v "/pfad/zum/repo:/target:ro" \
  secscore --mode scan --target /target
```
Mit festem Dateinamen (Pfad muss in einem gemounteten Ordner liegen):
```bash
docker run --rm \
  -v "$(pwd)/reports:/app/reports" \
  -v "/pfad/zum/repo:/target:ro" \
  secscore --mode scan --target /target --output /app/reports/mein_report.json
```
Oder direkt nach stdout in eine lokale Datei umleiten (ohne reports-Mount):
```bash
docker run --rm -v "/pfad/zum/repo:/target:ro" secscore \
  --mode scan --target /target --output - > report.json
```
> Wichtig: Der Container ist mit `--rm` fluechtig. Ein Report ueberlebt nur, wenn er in
> einen gemounteten Ordner geschrieben (`--output /app/reports/...` bzw. Default
> `reports/`) oder nach stdout umgeleitet wird. Ein roher Host-Pfad als `--output`
> funktioniert nicht – der Container kennt nur gemountete Pfade.

**Nur einen Unterordner scannen und Ordner ausschliessen:**
```bash
docker run --rm \
  -v "$(pwd)/reports:/app/reports" \
  -v "/pfad/zum/repo:/target:ro" \
  secscore --mode scan --target /target --subdir backend --exclude-dirs tests,docs
```

**IaC-Daten aus bestehenden Sprach-Benchmarks in benchmark_iac.json exportieren**
(einmalig, keine Scanner/kein Token noetig):
```bash
docker run --rm -v "$(pwd)/benchmarks:/app/benchmarks" secscore --export-iac
```

## Flags

| Flag | Bedeutung |
|------|-----------|
| `--mode {score,scan}` | Betriebsart: `score` = Bewertung, `scan` = reiner Report. |
| `--target PFAD` | Pfad zum Ziel-Repo im Container (z. B. `/target`). |
| `--subdir NAME` | Nur diesen Unterordner des Ziel-Repos scannen (z. B. `backend`). |
| `--exclude-dirs A,B` | Kommagetrennte Ordner-/Datei-Namen (glob), die vom Scan ausgeschlossen werden. |
| `--languages A,B` | Zu scannende Sprachen (z. B. `python,typescript`). `javascript` wird als `typescript` behandelt. |
| `--compare-repos N` | Gegen wie viele der populaersten Referenz-Repos je Sprache verglichen wird (Standard: alle). |
| `--repos N` | Anzahl Repos beim Neubau einer Benchmark (Standard 100; ueberspringt die j/n-Abfrage). |
| `--token TOKEN` | GitHub-Token (alternativ Umgebungsvariable `GITHUB_TOKEN`). |
| `--output ZIEL` | Report-Ziel (scan- und score-Modus): Dateipfad, Ordner, oder `-` fuer stdout. |
| `--export-iac` | IaC-Daten der Sprach-Benchmarks in `benchmark_iac.json` exportieren und beenden. |
| `--score-config DATEI` | Optionale JSON-Konfiguration fuer Gewichte/Severity-Mapping. |

Nicht angegebene Parameter werden im interaktiven Modus abgefragt.
