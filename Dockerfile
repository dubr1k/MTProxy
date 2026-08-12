# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04 AS builder
ARG MTPROXY_COMMIT=f36d8af769ffaeac36978d38c2c0f6d1104c2137
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates git libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/TelegramMessenger/MTProxy.git /src \
    && cd /src \
    && git checkout --detach "$MTPROXY_COMMIT" \
    && make -j"$(nproc)" \
    && strip objs/bin/mtproto-proxy

FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin mtproxy \
    && mkdir -p /app /run/mtproxy \
    && chown mtproxy:mtproxy /run/mtproxy
COPY --from=builder /src/objs/bin/mtproto-proxy /usr/local/bin/mtproto-proxy
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh
WORKDIR /app
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
