#!/bin/bash
# build_icns.sh — draw the app icon and pack it as gui/Resources/AppIcon.icns (macOS: sips, iconutil).
#
#   gui/icon/build_icns.sh            writes ../Resources/AppIcon.icns next to this script's folder
#
# Only needed when make_icon.py changes; the .icns is tracked, so a normal build does not run this.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../Resources/AppIcon.icns"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 "$HERE/make_icon.py" "$WORK/icon-1024.png"
SET="$WORK/AppIcon.iconset"
mkdir -p "$SET"
for s in 16 32 128 256 512; do
    sips -z "$s" "$s" "$WORK/icon-1024.png" --out "$SET/icon_${s}x${s}.png" >/dev/null
    d=$((s * 2))
    sips -z "$d" "$d" "$WORK/icon-1024.png" --out "$SET/icon_${s}x${s}@2x.png" >/dev/null
done
mkdir -p "$(dirname "$OUT")"
iconutil -c icns "$SET" -o "$OUT"
echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
