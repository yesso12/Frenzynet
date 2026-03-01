#!/usr/bin/env bash
set -euo pipefail

BROWSER="${1:-chrome}"
BASE_URL="https://frenzynets.com/frenzynet-updates"
TARGET_DIR="$HOME/Downloads/FlickFuse-Extension"
mkdir -p "$TARGET_DIR"

ZIP="flickfuse-extension-chromium-latest.zip"
if [[ "$BROWSER" == "firefox" ]]; then
  ZIP="flickfuse-extension-firefox-latest.zip"
fi

ZIP_PATH="$TARGET_DIR/$ZIP"
EXTRACT_PATH="$TARGET_DIR/${ZIP%.zip}"

curl -fsSL "$BASE_URL/$ZIP" -o "$ZIP_PATH"
rm -rf "$EXTRACT_PATH"
unzip -q -o "$ZIP_PATH" -d "$EXTRACT_PATH"

echo "FlickFuse files extracted: $EXTRACT_PATH"

case "$BROWSER" in
  chrome) xdg-open "chrome://extensions/" >/dev/null 2>&1 || true ;;
  edge) xdg-open "edge://extensions/" >/dev/null 2>&1 || true ;;
  brave) xdg-open "brave://extensions/" >/dev/null 2>&1 || true ;;
  opera) xdg-open "opera://extensions/" >/dev/null 2>&1 || true ;;
  firefox) xdg-open "https://addons.mozilla.org/en-US/firefox/search/?q=flickfuse" >/dev/null 2>&1 || true ;;
  *) xdg-open "chrome://extensions/" >/dev/null 2>&1 || true ;;
esac

xdg-open "$EXTRACT_PATH" >/dev/null 2>&1 || true

echo "Enable Developer Mode and click Load Unpacked for Chromium browsers."
