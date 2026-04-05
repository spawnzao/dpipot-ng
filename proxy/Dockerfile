# syntax=docker/dockerfile:1

# ---- stage 1: build ----
FROM golang:1.22-alpine AS builder

# instala dependências de build para confluent-kafka-go (requer CGO)
RUN apk add --no-cache gcc musl-dev librdkafka-dev pkgconf

WORKDIR /app

# copia go.mod e go.sum primeiro para aproveitar cache de layers
COPY go.mod go.sum ./
RUN go mod download

# copia o código fonte
COPY . .

# compila o binário
# CGO_ENABLED=1 necessário para confluent-kafka-go
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /proxy \
    ./cmd/proxy

# ---- stage 2: runtime mínimo ----
FROM alpine:3.19

# librdkafka necessária em runtime (confluent-kafka-go usa CGO)
RUN apk add --no-cache librdkafka ca-certificates

# cria usuário não-root para rodar o proxy
RUN adduser -D -u 1000 proxy

COPY --from=builder /proxy /proxy

USER proxy

# porta padrão do proxy
EXPOSE 8080

ENTRYPOINT ["/proxy"]
