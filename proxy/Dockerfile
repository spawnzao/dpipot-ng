# syntax=docker/dockerfile:1

# ── stage 1: build proxy Go ─────────────────────────────────────────────
FROM golang:1.26-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    librdkafka-dev \
    libpcap-dev \
    libjson-c-dev \
    git \
    autoconf \
    automake \
    libtool \
    && rm -rf /var/lib/apt/lists/*

# Build nDPI 4.12 from source
RUN rm -rf /usr/local/include/ndpi /usr/local/lib/libndpi* && \
    cd /tmp && \
    git clone --depth 1 --branch 4.12-stable https://github.com/ntop/nDPI.git && \
    cd nDPI && \
    ./autogen.sh && \
    ./configure --prefix=/usr/local --enable-experimental-features && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    rm -rf /tmp/nDPI /tmp/nDPI-*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 CGO_CFLAGS="-I/usr/local/include" CGO_LDFLAGS="-L/usr/local/lib -lndpi -lpcap -lpthread -lm" \
    go build -ldflags="-s -w" -o /proxy ./cmd/proxy

# ── stage 2: runtime mínimo ─────────────────────────────────────────────
FROM debian:bookworm AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    librdkafka1 \
    ca-certificates \
    libpcap0.8 \
    libjson-c5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy nDPI libs from builder
COPY --from=builder /usr/local/lib/libndpi.so.4.12.0 /usr/local/lib/libndpi.so.4.12.0
COPY --from=builder /usr/local/lib/libndpi.so.4 /usr/local/lib/libndpi.so.4
COPY --from=builder /usr/local/lib/libndpi.so /usr/local/lib/libndpi.so

ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

RUN id -u proxy 2>/dev/null || useradd -u 1000 -m proxy

COPY --from=builder /proxy /proxy

USER proxy
EXPOSE 8080
ENTRYPOINT ["/proxy"]