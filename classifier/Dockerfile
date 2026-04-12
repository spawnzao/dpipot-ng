# syntax=docker/dockerfile:1

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go \
    libpcap-dev \
    git \
    make \
    gcc \
    libc-dev \
    ca-certificates \
    autoconf \
    automake \
    libtool \
    pkg-config \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp && \
    git clone --depth 1 --branch 4.12-stable https://github.com/ntop/nDPI.git && \
    cd nDPI && \
    ./autogen.sh && \
    ./configure --enable-experimental-features && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd / && rm -rf nDPI

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -mod=mod -o classifier ./cmd

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/libndpi.so.5 /usr/local/lib/libndpi.so.5
COPY --from=builder /usr/local/lib/libndpi.so /usr/local/lib/libndpi.so
COPY --from=builder /usr/local/include /usr/local/include

RUN ldconfig

COPY --from=builder /build/classifier /classifier

RUN mkdir -p /var/run/dpipot && chmod 777 /var/run/dpipot

ENTRYPOINT ["/classifier"]