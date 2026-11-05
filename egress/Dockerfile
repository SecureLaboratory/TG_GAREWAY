# Egress proxy: the only way from the internal networks to the internet.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends squid \
 && rm -rf /var/lib/apt/lists/*
COPY squid.conf /etc/squid/squid.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
EXPOSE 3128 3129 3130
ENTRYPOINT ["/entrypoint.sh"]
