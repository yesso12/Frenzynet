#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT_DIR="$ROOT/browser-extension/frenzy-telewatch-extension"
OUT_DIR="$ROOT/site/frenzynet-updates"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
OUT_ZIP="$OUT_DIR/frenzy-telewatch-extension-${STAMP}.zip"
LATEST_ZIP="$OUT_DIR/frenzy-telewatch-extension-latest.zip"

mkdir -p "$OUT_DIR"
if [[ ! -d "$EXT_DIR" ]]; then
  echo "Extension dir not found: $EXT_DIR" >&2
  exit 1
fi

cd "$EXT_DIR"
zip -r "$OUT_ZIP" . -x "*.DS_Store" >/dev/null
cp -f "$OUT_ZIP" "$LATEST_ZIP"

echo "Created: $OUT_ZIP"
echo "Updated: $LATEST_ZIP"
