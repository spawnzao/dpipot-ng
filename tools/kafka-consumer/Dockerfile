# Kafka Consumer - para testar eventos do dpipot
FROM golang:1.21 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -o consumer .

FROM debian:bookworm-slim
COPY --from=builder /build/consumer /usr/local/bin/
ENTRYPOINT ["consumer"]
