# OpenRoost360 server image. Built from this repository by `docker compose build` (or update.sh).
FROM python:3.13-slim-trixie

ARG GIT_COMMIT=unknown
# iptables: OpenRoost keeps the hub's port 443 -> listener redirect in place (needs NET_ADMIN, granted in compose.yaml)
COPY requirements.txt /tmp/requirements.txt
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir -r /tmp/requirements.txt \
 && python -c "import vodozemac, cryptography"

WORKDIR /app
COPY openroost ./openroost
COPY web ./web

ENV OPENROOST_DATA=/data \
    OPENROOST_IN_DOCKER=1 \
    OPENROOST_BUILD=${GIT_COMMIT} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

LABEL org.opencontainers.image.title="OpenRoost360" \
      org.opencontainers.image.description="Local stand-in for Roost's Security360 cloud" \
      org.opencontainers.image.source="https://git.tysstech.com/TySS-Dev/OpenRoost360" \
      org.opencontainers.image.revision="${GIT_COMMIT}"

VOLUME ["/data"]
EXPOSE 8443 8362 8883

HEALTHCHECK --interval=30s --timeout=8s --start-period=20s --retries=3 CMD python -c "import os,ssl,urllib.request as u; t=os.environ.get('OPENROOST_TLS','on').lower() not in ('off','0','false','no'); p=os.environ.get('OPENROOST_HTTPS_PORT','8443') if t else os.environ.get('OPENROOST_HTTP_PORT','8362'); c=ssl._create_unverified_context(); u.urlopen(f\"{'https' if t else 'http'}://127.0.0.1:{p}/api/v1/status\", timeout=5, context=c if t else None)"

ENTRYPOINT ["python", "-m", "openroost"]
