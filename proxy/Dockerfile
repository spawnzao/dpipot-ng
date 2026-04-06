# syntax=docker/dockerfile:1

# ── stage 1: build ──────────────────────────────────────────────────
FROM golang:1.24.3-bookworm AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    librdkafka-dev \
    ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /proxy \
    ./cmd/proxy

# ── stage 2: runtime mínimo ─────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    librdkafka1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 1000 -m proxy

COPY --from=builder /proxy /proxy

USER proxy
EXPOSE 8080
ENTRYPOINT ["/proxy"]
