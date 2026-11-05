#!/bin/sh
# Writes the two allowlists from the environment, then runs Squid in the foreground.
# Squid's worker can't write to the container's stdout, so it logs to files that are streamed.
set -e
echo "$BROWSER_ALLOWED_DOMAINS" | tr ', ' '\n\n' | sed '/^$/d' > /etc/squid/browser_domains.txt
echo "$SERVICE_ALLOWED_DOMAINS" | tr ', ' '\n\n' | sed '/^$/d' > /etc/squid/service_domains.txt
echo "browser allowlist: $(tr '\n' ' ' < /etc/squid/browser_domains.txt)"
echo "service allowlist: $(tr '\n' ' ' < /etc/squid/service_domains.txt)"
mkdir -p /var/log/squid && touch /var/log/squid/access.log /var/log/squid/cache.log
chown -R proxy:proxy /var/log/squid
tail -qF /var/log/squid/access.log /var/log/squid/cache.log &
exec squid -N -f /etc/squid/squid.conf
