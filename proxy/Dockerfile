# syntax=docker/dockerfile:1

# ── stage 1: build ──────────────────────────────────────────────────
FROM golang:1.26-bookworm AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    librdkafka-dev \
    ca-certificates \
    wget \
    git \
    libpcap-dev \
    libjson-c-dev \
    libmaxminddb-dev \
    libgcrypt20-dev \
    libgpg-error-dev \
    autoconf \
    automake \
    libtool

# Build nDPI 4.12 e copia headers para local acessível
RUN cd /tmp && \
    git clone --branch 4.12-stable --depth=1 https://github.com/ntop/nDPI.git && \
    cd nDPI && \
    ./autogen.sh && \
    ./configure --prefix=/usr && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cp -r src/include/* /usr/include/ && \
    rm -rf /tmp/nDPI

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

# Copia bibliotecas e headers nDPI do builder
COPY --from=builder /usr/lib/libndpi.so.4 /usr/lib/libndpi.so.4
COPY --from=builder /usr/lib/libndpi.so /usr/lib/libndpi.so
COPY --from=builder /usr/include/ndpi /usr/include/ndpi
COPY --from=builder /usr/lib/x86_64-linux-gnu/libmaxminddb.so.0 /usr/lib/x86_64-linux-gnu/libmaxminddb.so.0
COPY --from=builder /usr/lib/x86_64-linux-gnu/libmaxminddb.so /usr/lib/x86_64-linux-gnu/libmaxminddb.so
COPY --from=builder /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so.0.8
COPY --from=builder /usr/lib/x86_64-linux-gnu/libgcrypt.so.20 /usr/lib/x86_64-linux-gnu/libgcrypt.so.20
COPY --from=builder /usr/lib/x86_64-linux-gnu/libgpg-error.so.0 /usr/lib/x86_64-linux-gnu/libgpg-error.so.0
COPY --from=builder /usr/lib/x86_64-linux-gnu/libjson-c.so.5 /usr/lib/x86_64-linux-gnu/libjson-c.so.5
RUN ldconfig

RUN apt-get update && apt-get install -y \
    librdkafka1 \
    ca-certificates \
    libpcap0.8 \
    libjson-c5 \
    libgcrypt20 \
    libgpg-error0 \
    libmaxminddb0 \
    && rm -rf /var/lib/apt/lists/*

RUN id -u proxy 2>/dev/null || useradd -u 1000 -m proxy

COPY --from=builder /proxy /proxy

USER proxy
EXPOSE 8080
ENTRYPOINT ["/proxy"]