#!/bin/bash
set -euo pipefail

BROWSER="${1:-chrome}"
BASE_URL="https://frenzynets.com/frenzynet-updates"
TARGET_DIR="$HOME/Downloads/FlickFuse-Extension"
mkdir -p "$TARGET_DIR"

ZIP="flickfuse-extension-chromium-latest.zip"
if [ "$BROWSER" = "firefox" ]; then
  ZIP="flickfuse-extension-firefox-latest.zip"
fi

ZIP_PATH="$TARGET_DIR/$ZIP"
EXTRACT_PATH="$TARGET_DIR/${ZIP%.zip}"

curl -fsSL "$BASE_URL/$ZIP" -o "$ZIP_PATH"
rm -rf "$EXTRACT_PATH"
unzip -q -o "$ZIP_PATH" -d "$EXTRACT_PATH"
open "$EXTRACT_PATH"

case "$BROWSER" in
  chrome) open "chrome://extensions/" ;;
  edge) open "microsoft-edge://extensions/" ;;
  brave) open "brave://extensions/" ;;
  opera) open "opera://extensions/" ;;
  firefox) open "https://addons.mozilla.org/en-US/firefox/search/?q=flickfuse" ;;
  *) open "chrome://extensions/" ;;
esac

echo "FlickFuse files are ready at: $EXTRACT_PATH"
echo "Enable Developer Mode and click Load Unpacked for Chromium browsers."
