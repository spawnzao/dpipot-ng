# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder

RUN apk add --no-cache \
    libpcap-dev \
    git \
    make \
    gcc \
    musl-dev \
    linux-headers \
    autoconf \
    automake \
    libtool \
    pkgconfig \
    cargo \
    && rm -rf /var/cache/apk/*

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

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 CGO_CFLAGS="-I/usr/local/include" CGO_LDFLAGS="-L/usr/local/lib -lndpi" GOOS=linux go build -mod=mod -o classifier ./cmd

FROM alpine:3.19

RUN apk add --no-cache libpcap

COPY --from=builder /usr/local/lib/libndpi.so.4.12.0 /usr/local/lib/libndpi.so.4.12.0
COPY --from=builder /usr/local/lib/libndpi.so.4 /usr/local/lib/libndpi.so.4
COPY --from=builder /usr/local/lib/libndpi.so /usr/local/lib/libndpi.so
COPY --from=builder /usr/local/include /usr/local/include

RUN mkdir -p /etc/ld.so.conf.d && echo "/usr/local/lib" > /etc/ld.so.conf.d/ndpi.conf && ldconfig

COPY --from=builder /build/classifier /classifier

RUN mkdir -p /var/run/dpipot && chmod 777 /var/run/dpipot

ENTRYPOINT ["/classifier"]