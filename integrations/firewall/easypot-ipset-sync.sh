#!/usr/bin/env bash
# Pull the EasyPot blocklist into an ipset and drop it at the host firewall.
# Run from cron every minute:  * * * * * /usr/local/bin/easypot-ipset-sync.sh
#
#   EASYPOT_FEED_URL=https://easypot.example.com:8081/feeds/blocklist.txt
#   EASYPOT_FEED_TOKEN=...   (the admin.feedToken from easypot config)
set -euo pipefail

FEED_URL="${EASYPOT_FEED_URL:?set EASYPOT_FEED_URL}"
TOKEN="${EASYPOT_FEED_TOKEN:?set EASYPOT_FEED_TOKEN}"
SET="easypot"
TMP_SET="${SET}_tmp"

command -v ipset >/dev/null || { echo "ipset not installed" >&2; exit 1; }

list="$(curl -fsS --max-time 10 -H "Authorization: Bearer ${TOKEN}" "${FEED_URL}")"

ipset create -exist "${SET}" hash:ip family inet timeout 0
ipset create -exist "${TMP_SET}" hash:ip family inet timeout 0
ipset flush "${TMP_SET}"

while IFS= read -r ip; do
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && ipset add -exist "${TMP_SET}" "$ip"
done <<< "$list"

# Atomic swap so there's never a window with an empty set.
ipset swap "${TMP_SET}" "${SET}"
ipset destroy "${TMP_SET}"

iptables -C INPUT -m set --match-set "${SET}" src -j DROP 2>/dev/null \
  || iptables -I INPUT -m set --match-set "${SET}" src -j DROP

echo "easypot: $(ipset list "${SET}" | grep -c '^[0-9]') IPs blocked"
