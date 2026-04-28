# ── stage 1: build proxy Go ─────────────────────────────────────────────
FROM golang:1.26-bookworm AS builder

# Install build dependencies
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

# Copy source code
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Debug: list files to verify structure
RUN find /app -name "legitimate_paths.yaml" -o -name "classifier.go" -path "*/httpclassifier/*" | head -10

# Build the proxy
RUN CGO_ENABLED=1 CGO_CFLAGS="-I/usr/local/include" CGO_LDFLAGS="-L/usr/local/lib -lndpi -lpcap -lpthread -lm" \
    go build -ldflags="-s -w" -o /proxy ./cmd/proxy

# ── stage 2: runtime mínimo ─────────────────────────────────────────────
FROM debian:bookworm AS runner

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    librdkafka1 \
    ca-certificates \
    libpcap0.8 \
    libjson-c5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy nDPI libraries from builder
COPY --from=builder /usr/local/lib/libndpi.so.4.12.0 /usr/local/lib/libndpi.so.4.12.0
COPY --from=builder /usr/local/lib/libndpi.so.4 /usr/local/lib/libndpi.so.4
COPY --from=builder /usr/local/lib/libndpi.so /usr/local/lib/libndpi.so

# Set library path
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

# Create proxy user
RUN id -u proxy 2>/dev/null || useradd -u 1000 -m proxy

# Copy the built binary
COPY --from=builder /proxy /proxy

# Copy the httpclassifier configuration file
#COPY --from=builder /app/proxy/internal/httpclassifier/legitimate_paths.yaml /app/proxy/internal/httpclassifier/legitimate_paths.yaml
COPY internal/httpclassifier/legitimate_paths.yaml /etc/dpipot/legitimate_paths.yaml

# Run as non-root user
USER proxy

# Expose port and set entrypoint
EXPOSE 8080
ENTRYPOINT ["/proxy"]