# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    librdkafka-dev \
    libpcap-dev \
    git \
    make \
    autoconf \
    automake \
    libtool \
    cargo \
    && rm -rf /var/lib/apt/lists/*

RUN rm -rf /usr/include/ndpi /usr/local/include/ndpi && \
    cd /tmp && \
    git clone --depth 1 --branch 4.12-stable https://github.com/ntop/nDPI.git && \
    cd nDPI && \
    ./autogen.sh && \
    ./configure --prefix=/usr/local --enable-experimental-features && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    rm -rf /tmp/nDPI /tmp/nDPI-*

WORKDIR /build

COPY . .

RUN CGO_ENABLED=1 \
    CGO_CFLAGS="-I/usr/local/include" \
    CGO_LDFLAGS="-L/usr/local/lib -lndpi -lpcap -lpthread -lm -lrdkafka" \
    GOOS=linux \
    go build -mod=mod -ldflags="-s -w" -o /dpipot ./cmd/dpipot

FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    librdkafka1 \
    libpcap0.8 \
    ca-certificates \
    libjson-c5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

COPY --from=builder /usr/local/lib/libndpi.so.4.12.0 /usr/local/lib/libndpi.so.4.12.0
COPY --from=builder /usr/local/lib/libndpi.so.4       /usr/local/lib/libndpi.so.4
COPY --from=builder /usr/local/lib/libndpi.so         /usr/local/lib/libndpi.so

ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

RUN groupadd -r dpipot && useradd -r -g dpipot dpipot

COPY --from=builder /dpipot /dpipot
COPY --from=builder /build/internal/httpclassifier/legitimate_paths.yaml /etc/dpipot/legitimate_paths.yaml

RUN mkdir -p /var/run/dpipot && chown dpipot:dpipot /var/run/dpipot

USER dpipot

EXPOSE 8080 8081

ENTRYPOINT ["/dpipot"]
