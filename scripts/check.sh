#!/usr/bin/env bash
# Checker HTTP externe ultra-rapide — ports 80/443
# Pipeline: massdns → masscan → httpx
#
# Usage:
#   bash scripts/check.sh domains.txt [alive.txt]
#   bash scripts/check.sh domains.txt alive.txt 200000

set -euo pipefail

INPUT="${1:-}"
OUTPUT="${2:-output/alive_$(date +%s).txt}"
MASSCAN_RATE="${3:-100000}"

if [[ -z "$INPUT" || ! -f "$INPUT" ]]; then
  echo "Usage: $0 <domains.txt> [alive.txt] [masscan_rate]"
  exit 1
fi

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[ERR] '$1' manquant — lance: bash scripts/install-verify-tools.sh"
    exit 1
  }
}

need massdns
need masscan
need httpx

mkdir -p "$(dirname "$OUTPUT")" output /tmp/dg-check
WORKDIR=$(mktemp -d /tmp/dg-check/run.XXXXXX)
trap 'rm -rf "$WORKDIR"' EXIT

DOMAINS="$WORKDIR/domains.txt"
RESOLVERS="$WORKDIR/resolvers.txt"
DNS_OUT="$WORKDIR/dns.txt"
IPS="$WORKDIR/ips.txt"
MASSCAN_OUT="$WORKDIR/masscan.json"
OPEN_IPS="$WORKDIR/open_ips.txt"
CANDIDATES="$WORKDIR/candidates.txt"

# Normalise: 1 domaine / ligne
awk '
  NF && $0 !~ /^#/ {
    d=$0
    if (d ~ /^\{/) next
    gsub(/\r/,"",d)
    gsub(/^\*\./,"",d)
    print tolower(d)
  }
' "$INPUT" | awk '!seen[$0]++' > "$DOMAINS"

TOTAL=$(wc -l < "$DOMAINS" | tr -d ' ')
echo "[CHECK] $TOTAL domaines | massdns → masscan → httpx"
echo "[CHECK] rate masscan=${MASSCAN_RATE} pps"

# Resolvers
if [[ -f resolvers.txt ]]; then
  cp resolvers.txt "$RESOLVERS"
else
  cat > "$RESOLVERS" <<'EOF'
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
EOF
fi

START=$(date +%s)
LOG_PID=""

log_loop() {
  while true; do
    sleep 3
    ALIVE=0
    [[ -f "$OUTPUT" ]] && ALIVE=$(wc -l < "$OUTPUT" | tr -d ' ')
    NOW=$(date +%s)
    ELAPSED=$((NOW - START))
    [[ $ELAPSED -lt 1 ]] && ELAPSED=1
    RATE=$((ALIVE / ELAPSED))
    echo "[CHECK] alive=$ALIVE | ${RATE} domain/s | ${ELAPSED}s"
  done
}

# 1) massdns
echo "[1/3] massdns..."
massdns -r "$RESOLVERS" -t A -o S -w "$DNS_OUT" -s 10000 "$DOMAINS" >/dev/null 2>&1 || true

# domain -> IPs map + unique IPs
awk '$2=="A"{
  d=$1; sub(/\.$/,"",d);
  ip=$3;
  print d, ip
}' "$DNS_OUT" | tee "$WORKDIR/dom_ip.txt" | awk '{print $2}' | awk '!seen[$0]++' > "$IPS"

RESOLVED=$(wc -l < "$WORKDIR/dom_ip.txt" | tr -d ' ')
UNIQUE_IPS=$(wc -l < "$IPS" | tr -d ' ')
echo "[1/3] DNS: $RESOLVED domain→IP | $UNIQUE_IPS IPs uniques"

# 2) masscan 80,443
echo "[2/3] masscan -p80,443 --rate $MASSCAN_RATE ..."
if [[ "$UNIQUE_IPS" -eq 0 ]]; then
  echo "[ERR] aucune IP résolue"
  exit 1
fi

# masscan needs root for high speed; try anyway
masscan -iL "$IPS" -p80,443 --rate "$MASSCAN_RATE" -oJ "$MASSCAN_OUT" --wait 0 2>/dev/null \
  || sudo masscan -iL "$IPS" -p80,443 --rate "$MASSCAN_RATE" -oJ "$MASSCAN_OUT" --wait 0

# IPs with 80 or 443 open
python3 - "$MASSCAN_OUT" "$OPEN_IPS" <<'PY'
import json, sys
path, out = sys.argv[1], sys.argv[2]
open_ips = set()
raw = open(path, encoding="utf-8", errors="ignore").read().strip()
if not raw:
    open(out, "w").close()
    raise SystemExit
# masscan -oJ can be array or ndjson
try:
    data = json.loads(raw)
    entries = data if isinstance(data, list) else [data]
except json.JSONDecodeError:
    entries = []
    for line in raw.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass
for e in entries:
    if isinstance(e, dict) and e.get("ip") and e.get("ports"):
        for p in e["ports"]:
            if int(p.get("port", 0)) in (80, 443):
                open_ips.add(e["ip"])
                break
open(out, "w").write("\n".join(sorted(open_ips)) + ("\n" if open_ips else ""))
print(f"[2/3] ports ouverts: {len(open_ips)} IPs")
PY

# Domains whose IP has open port
awk 'NR==FNR{open[$1]=1; next} ($2 in open){print $1}' "$OPEN_IPS" "$WORKDIR/dom_ip.txt" \
  | awk '!seen[$0]++' > "$CANDIDATES"

CAND=$(wc -l < "$CANDIDATES" | tr -d ' ')
echo "[2/3] candidats HTTP: $CAND domaines"

# 3) httpx
echo "[3/3] httpx..."
: > "$OUTPUT"
log_loop &
LOG_PID=$!

httpx -l "$CANDIDATES" \
  -threads 500 \
  -timeout 3 \
  -silent \
  -status-code \
  -follow-redirects \
  -no-color \
  -o "$WORKDIR/httpx.txt" >/dev/null 2>&1 || true

# Extract hosts (httpx default line is URL)
awk '{
  u=$1
  gsub(/^https?:\/\//,"",u)
  split(u,a,"/")
  host=a[1]
  split(host,b,":")
  print b[1]
}' "$WORKDIR/httpx.txt" | awk 'NF && !seen[$0]++' > "$OUTPUT"

kill "$LOG_PID" 2>/dev/null || true
wait "$LOG_PID" 2>/dev/null || true

ALIVE=$(wc -l < "$OUTPUT" | tr -d ' ')
END=$(date +%s)
ELAPSED=$((END - START))
[[ $ELAPSED -lt 1 ]] && ELAPSED=1
RATE=$((ALIVE / ELAPSED))

echo "[DONE] $ALIVE/$TOTAL ALIVE | ${RATE} domain/s avg | ${ELAPSED}s | → $OUTPUT"
