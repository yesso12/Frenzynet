#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/site/frenzynet-updates"
META_DIR="$ROOT/browser-extension/store-submission"
CHROMIUM_ZIP="$OUT_DIR/flickfuse-extension-chromium-latest.zip"
FIREFOX_ZIP="$OUT_DIR/flickfuse-extension-firefox-latest.zip"
STAMP="$(date -u +%Y%m%d-%H%M%S)"

mkdir -p "$OUT_DIR"
TMP="/tmp/flickfuse-store-submission-$STAMP"
mkdir -p "$TMP"

cp -a "$META_DIR/." "$TMP/"
cp -f "$CHROMIUM_ZIP" "$TMP/"
cp -f "$FIREFOX_ZIP" "$TMP/"
cp -f "$OUT_DIR/install-flickfuse-windows.ps1" "$TMP/"
cp -f "$OUT_DIR/install-flickfuse-macos.command" "$TMP/"
cp -f "$OUT_DIR/install-flickfuse-linux.sh" "$TMP/"

OUT_ZIP="$OUT_DIR/flickfuse-store-submission-$STAMP.zip"
OUT_LATEST="$OUT_DIR/flickfuse-store-submission-latest.zip"
(
  cd "$TMP"
  zip -r "$OUT_ZIP" . >/dev/null
)
cp -f "$OUT_ZIP" "$OUT_LATEST"
rm -rf "$TMP"

echo "Created: $OUT_ZIP"
echo "Updated: $OUT_LATEST"
