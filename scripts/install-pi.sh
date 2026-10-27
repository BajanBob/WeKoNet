#!/usr/bin/env bash
# Install WeKoNet on a Raspberry Pi 4/5 (64-bit Raspberry Pi OS).
# Usage: curl -fsSL https://raw.githubusercontent.com/<you>/wekonet/main/scripts/install-pi.sh | bash -s -- <you>/wekonet
set -euo pipefail
REPO="${1:?usage: install-pi.sh <owner>/<repo>}"
[ "$(uname -m)" = "aarch64" ] || { echo "Needs 64-bit Raspberry Pi OS (aarch64)"; exit 1; }
URL=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep -o 'https://[^"]*arm64\.deb' | head -1)
[ -n "$URL" ] || { echo "No arm64 .deb in latest release"; exit 1; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/wekonet.deb" "$URL"
sudo apt-get install -y "$TMP/wekonet.deb"
xdg-mime default wekonet.desktop x-scheme-handler/wekonet || true
echo "WeKoNet installed. Launch it from the menu, or open a wekonet:// beacon link."
