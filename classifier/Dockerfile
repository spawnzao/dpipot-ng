# syntax=docker/dockerfile:1

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go \
    libpcap-dev \
    libndpi-dev \
    git \
    make \
    gcc \
    libc-dev \
    ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -mod=mod -o classifier ./cmd

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libndpi4.2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/classifier /classifier

RUN mkdir -p /var/run/dpipot && chmod 777 /var/run/dpipot

ENTRYPOINT ["/classifier"]