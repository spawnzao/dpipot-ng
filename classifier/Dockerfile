# syntax=docker/dockerfile:1

# ── stage 1: compila nDPI a partir do repositório oficial ────────────
FROM ubuntu:24.04 AS ndpi-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libpcap-dev \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libgcrypt-dev \
    libjson-c-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# clona e compila a versão mais atual do nDPI
RUN git clone --depth=1 https://github.com/ntop/nDPI.git /ndpi
WORKDIR /ndpi
RUN ./autogen.sh && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install

# ── stage 2: compila o classifier ────────────────────────────────────
FROM ubuntu:24.04 AS classifier-builder

# copia o nDPI já compilado do stage anterior
COPY --from=ndpi-builder /usr/local /usr/local

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    libgcrypt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN make

# ── stage 3: imagem de runtime mínima ────────────────────────────────
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libgcrypt20 \
    && rm -rf /var/lib/apt/lists/*

# copia as libs do nDPI e o binário
COPY --from=ndpi-builder /usr/local/lib/libndpi* /usr/local/lib/
COPY --from=classifier-builder /app/classifier /classifier

RUN ldconfig

# cria usuário não-root
RUN useradd -u 1001 -r -s /sbin/nologin classifier

# diretório do Unix socket — será montado como emptyDir pelo K8s
RUN mkdir -p /var/run/dpipot && chmod 777 /var/run/dpipot

USER classifier

ENTRYPOINT ["/classifier", "/var/run/dpipot/ndpi.sock"]
