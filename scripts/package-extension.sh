#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT_DIR="$ROOT/browser-extension/frenzy-telewatch-extension"
OUT_DIR="$ROOT/site/frenzynet-updates"
STAMP="$(date -u +%Y%m%d-%H%M%S)"

mkdir -p "$OUT_DIR"
if [[ ! -d "$EXT_DIR" ]]; then
  echo "Extension dir not found: $EXT_DIR" >&2
  exit 1
fi

TMP_BASE="/tmp/flickfuse-ext-${STAMP}"
mkdir -p "$TMP_BASE/chromium" "$TMP_BASE/firefox"

cp -a "$EXT_DIR/." "$TMP_BASE/chromium/"
cp -a "$EXT_DIR/." "$TMP_BASE/firefox/"

# Chromium bundle uses manifest.json
rm -f "$TMP_BASE/chromium/manifest.firefox.json"

# Firefox bundle swaps in manifest.firefox.json
if [[ -f "$TMP_BASE/firefox/manifest.firefox.json" ]]; then
  cp -f "$TMP_BASE/firefox/manifest.firefox.json" "$TMP_BASE/firefox/manifest.json"
fi
rm -f "$TMP_BASE/firefox/manifest.firefox.json"

CHROMIUM_STAMP="$OUT_DIR/flickfuse-extension-chromium-${STAMP}.zip"
FIREFOX_STAMP="$OUT_DIR/flickfuse-extension-firefox-${STAMP}.zip"
CHROMIUM_LATEST="$OUT_DIR/flickfuse-extension-chromium-latest.zip"
FIREFOX_LATEST="$OUT_DIR/flickfuse-extension-firefox-latest.zip"

(
  cd "$TMP_BASE/chromium"
  zip -r "$CHROMIUM_STAMP" . -x "*.DS_Store" >/dev/null
)
(
  cd "$TMP_BASE/firefox"
  zip -r "$FIREFOX_STAMP" . -x "*.DS_Store" >/dev/null
)

cp -f "$CHROMIUM_STAMP" "$CHROMIUM_LATEST"
cp -f "$FIREFOX_STAMP" "$FIREFOX_LATEST"

rm -rf "$TMP_BASE"

echo "Created: $CHROMIUM_STAMP"
echo "Created: $FIREFOX_STAMP"
echo "Updated: $CHROMIUM_LATEST"
echo "Updated: $FIREFOX_LATEST"
