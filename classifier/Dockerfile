# syntax=docker/dockerfile:1

# ── stage 1: imagem de runtime mínima ────────────────────────────────
FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libndpi4.2 \
    && rm -rf /var/lib/apt/lists/*

COPY classifier /classifier

RUN mkdir -p /var/run/dpipot && chmod 777 /var/run/dpipot

ENTRYPOINT ["/classifier", "-interface=eth0", "-listen=127.0.0.1:9090", "-ttl=5"]