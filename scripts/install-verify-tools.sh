#!/usr/bin/env bash
# Installe les outils pour le pipeline verify max perf (root requis pour masscan)
set -euo pipefail

echo "=== Installation outils verify (massdns, masscan, httpx) ==="

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq git make gcc libpcap-dev curl unzip masscan 2>/dev/null || true
fi

# massdns
if ! command -v massdns >/dev/null 2>&1; then
  echo "Building massdns..."
  tmp=$(mktemp -d)
  git clone --depth 1 https://github.com/blechschmidt/massdns.git "$tmp/massdns"
  make -C "$tmp/massdns" -j"$(nproc)"
  cp "$tmp/massdns/bin/massdns" /usr/local/bin/
  rm -rf "$tmp"
fi

# httpx (ProjectDiscovery)
if ! command -v httpx >/dev/null 2>&1; then
  echo "Installing httpx..."
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || {
    curl -fsSL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip -o /tmp/httpx.zip
    unzip -o /tmp/httpx.zip httpx -d /usr/local/bin/
    chmod +x /usr/local/bin/httpx
  }
fi

echo ""
echo "Outils détectés:"
command -v massdns && massdns --version 2>/dev/null | head -1 || echo "  massdns: absent"
command -v masscan && masscan --version 2>/dev/null | head -1 || echo "  masscan: absent"
command -v httpx && httpx -version 2>/dev/null | head -1 || echo "  httpx: absent"
echo ""
echo "Usage: python3 main.py grab --verify --no-scan -t 60"
