# syntax=docker/dockerfile:1

# ── stage 1: build proxy Go ─────────────────────────────────────────────
FROM golang:1.26-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    librdkafka-dev \
    libpcap-dev \
    libjson-c-dev \
    libndpi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 CGO_CFLAGS="-I/usr/include" CGO_LDFLAGS="-lndpi -lpcap -lpthread -lm" \
    go build -ldflags="-s -w" -o /proxy ./cmd/proxy

# ── stage 2: runtime mínimo ─────────────────────────────────────────────
FROM debian:bookworm AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    librdkafka1 \
    ca-certificates \
    libpcap0.8 \
    libjson-c5 \
    libndpi4.2 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN id -u proxy 2>/dev/null || useradd -u 1000 -m proxy

COPY --from=0 /proxy /proxy

USER proxy
EXPOSE 8080
ENTRYPOINT ["/proxy"]