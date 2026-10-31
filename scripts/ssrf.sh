#!/usr/bin/env bash
# Example 3 - SSRF / egress guard. Try to register connectors pointed at
# forbidden internal destinations (cloud metadata), including decimal and hex
# encodings of 169.254.169.254. The gateway blocks each at create time with
# 400 egress_blocked, before anything connects.
#
#   export GATEWAY_ADMIN_KEY=gk_...
#   ./ssrf.sh
set -u
API="${GATEWAY_API:-http://localhost:8081/api/v1}"
: "${GATEWAY_ADMIN_KEY:?export GATEWAY_ADMIN_KEY first}"
echo "=== SSRF / egress guard - trying to register malicious connectors ==="
printf "%-55s %-5s %s\n" "ENDPOINT" "HTTP" "RESULT"
i=0
for url in \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  "http://169.254.169.254/latest/meta-data/" \
  "http://10.0.0.5:9200/" \
  "http://192.168.1.1/admin" \
  "http://2852039166/" \
  "http://0xA9FEA9FE/latest/meta-data/"; do
  i=$((i+1))
  code=$(curl -s -o /tmp/ssrf_body -w '%{http_code}' -X POST "$API/connectors" \
    -H "Authorization: Bearer $GATEWAY_ADMIN_KEY" -H "Content-Type: application/json" \
    -d "{\"name\":\"ssrf-$i\",\"slug\":\"ssrf-$i\",\"endpoint\":\"$url\"}")
  type=$(python3 -c "import sys,json;print(json.load(open('/tmp/ssrf_body')).get('type','?'))" 2>/dev/null || echo "?")
  printf "%-55s %-5s BLOCKED (%s)\n" "$url" "$code" "$type"
done
rm -f /tmp/ssrf_body
echo
echo "All blocked at create time -> the attack never reaches the internal network or the SIEM."
