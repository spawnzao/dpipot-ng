# syntax=docker/dockerfile:1

# ── stage 1: build ──────────────────────────────────────────────────
FROM golang:1.24.3-alpine AS builder

RUN apk add --no-cache gcc musl-dev librdkafka-dev pkgconf

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /proxy \
    ./cmd/proxy

# ── stage 2: runtime mínimo ─────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache librdkafka ca-certificates
RUN adduser -D -u 1000 proxy

COPY --from=builder /proxy /proxy

USER proxy
EXPOSE 8080
ENTRYPOINT ["/proxy"]
