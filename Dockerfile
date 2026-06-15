FROM python:3.12-slim

ARG TRIVY_VERSION=0.70.0
ARG SEMGREP_VERSION=1.157.0
ENV SEMGREP_SEND_METRICS=off

RUN apt-get update && apt-get install -y --no-install-recommends \
        git cloc curl tar gzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) asset="Linux-64bit" ;; \
        arm64) asset="Linux-ARM64" ;; \
        *) echo "Nicht unterstuetzte Architektur: $arch"; exit 1 ;; \
    esac; \
    url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${asset}.tar.gz"; \
    echo "Lade $url"; \
    curl -fsSL -o /tmp/trivy.tar.gz "$url"; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm -f /tmp/trivy.tar.gz; \
    trivy --version

RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" certifi \
    && semgrep --version

RUN trivy image --download-db-only \
    || echo "Hinweis: Trivy-DB-Vorabdownload uebersprungen - erfolgt beim ersten Scan."
RUN mkdir -p /tmp/warm && printf 'x = 1\n' > /tmp/warm/a.py \
    && semgrep scan --config p/default --metrics off --quiet /tmp/warm >/dev/null 2>&1 \
    ; rm -rf /tmp/warm ; true

WORKDIR /app
COPY security_score.py build_benchmark.py assess.py ./
RUN mkdir -p /app/benchmarks

VOLUME ["/app/benchmarks"]
ENTRYPOINT ["python3", "assess.py"]