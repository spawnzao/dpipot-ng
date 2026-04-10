# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git gcc musl-dev linux-headers libpcap-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o classifier ./cmd

FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libndpi4.2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/classifier /classifier

RUN mkdir -p /var/run/dpipot && chmod 777 /var/run/dpipot

ENTRYPOINT ["/classifier", "-interface=eth0", "-listen=127.0.0.1:9090", "-ttl=5"]