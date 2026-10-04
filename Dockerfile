# Forense-Framework in a container: web interface, CLI and PDF reports (Chromium).
#
#   docker build -t forense .
#   docker run --rm -p 127.0.0.1:8765:8765 -v "$PWD/cases:/cases" -v "/path/to/evidence:/evidence:ro" \
#              -e FORENSE_WEB_PASSWORD=change-me forense
#   docker run --rm -v "$PWD/cases:/cases" -v "/path/to/evidence:/evidence:ro" forense \
#              auto /evidence/laptop.E01 --new /cases/laptop
FROM python:3.12-slim

ARG WITH_MEMORY=0
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FORENSE_BROWSER=/usr/bin/chromium \
    FORENSE_WORKSPACE=/cases \
    FORENSE_CONFIG=/config/config.yaml

# Chromium prints the PDF reports; the fonts cover Latin text in the reports
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-dejavu-core fonts-liberation tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/forense
COPY pyproject.toml README.md README.en.md LICENSE ./
COPY forense ./forense
RUN if [ "$WITH_MEMORY" = "1" ]; then pip install ".[memory]"; else pip install .; fi \
 && rm -rf /opt/forense/build

RUN useradd --create-home --uid 1000 forense \
 && mkdir -p /cases /evidence /config \
 && chown forense:forense /cases /config
USER forense
WORKDIR /cases
VOLUME ["/cases", "/config"]
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=4)" || exit 1

ENTRYPOINT ["tini", "--", "forense"]
CMD ["web", "--host", "0.0.0.0", "--port", "8765", "-w", "/cases"]
