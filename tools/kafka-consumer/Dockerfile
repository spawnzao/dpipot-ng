# Kafka Consumer - para testar eventos do dpipot
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache gcc libc-dev librdkafka-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -o consumer .

FROM alpine:3.19
RUN apk add --no-cache librdkafka
COPY --from=builder /build/consumer /usr/local/bin/
ENTRYPOINT ["consumer"]
