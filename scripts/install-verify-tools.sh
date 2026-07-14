#!/usr/bin/env bash
# Installe massdns + masscan + httpx (root recommandé)
set -euo pipefail

echo "=== install massdns / masscan / httpx ==="

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq git make gcc libpcap-dev curl unzip ca-certificates 2>/dev/null || true
  sudo apt-get install -y -qq masscan 2>/dev/null || true
fi

# massdns
if ! command -v massdns >/dev/null 2>&1; then
  echo "[+] building massdns..."
  tmp=$(mktemp -d)
  git clone --depth 1 https://github.com/blechschmidt/massdns.git "$tmp/massdns"
  make -C "$tmp/massdns" -j"$(nproc)"
  sudo cp "$tmp/massdns/bin/massdns" /usr/local/bin/massdns
  rm -rf "$tmp"
fi

# httpx (ProjectDiscovery)
if ! command -v httpx >/dev/null 2>&1; then
  echo "[+] installing httpx..."
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) A=amd64 ;;
    aarch64|arm64) A=arm64 ;;
    *) A=amd64 ;;
  esac
  VER=$(curl -fsSL https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+' | head -1)
  VER="${VER:-v1.6.10}"
  URL="https://github.com/projectdiscovery/httpx/releases/download/${VER}/httpx_${VER#v}_linux_${A}.zip"
  curl -fsSL "$URL" -o /tmp/httpx.zip || curl -fsSL "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_${A}.zip" -o /tmp/httpx.zip
  unzip -o /tmp/httpx.zip httpx -d /usr/local/bin/ 2>/dev/null || sudo unzip -o /tmp/httpx.zip httpx -d /usr/local/bin/
  sudo chmod +x /usr/local/bin/httpx
fi

echo ""
echo "OK:"
command -v massdns && massdns 2>&1 | head -1 || true
command -v masscan && masscan --version 2>&1 | head -1 || true
command -v httpx && httpx -version 2>&1 | head -1 || true
echo ""
echo "Usage: bash scripts/check.sh domains.txt alive.txt"
