#!/bin/bash
set -e

APP_NAME="TG WS Proxy"
BUNDLE_DIR="${APP_NAME}.app"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Build release binary
echo "Building release binary..."
cargo build --release -p proxy-app

# Create .app bundle structure
rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR/Contents/MacOS"
mkdir -p "$BUNDLE_DIR/Contents/Resources"

# Copy files
cp "$PROJECT_DIR/target/release/proxy-app" "$BUNDLE_DIR/Contents/MacOS/"
cp "$SCRIPT_DIR/Info.plist" "$BUNDLE_DIR/Contents/"

# Convert PNG to ICNS if sips is available
if command -v sips &>/dev/null && command -v iconutil &>/dev/null; then
    ICONSET_DIR="$(mktemp -d)/icon.iconset"
    mkdir -p "$ICONSET_DIR"
    SRC_ICON="$PROJECT_DIR/assets/icon.png"
    sips -z 16 16     "$SRC_ICON" --out "$ICONSET_DIR/icon_16x16.png"     2>/dev/null
    sips -z 32 32     "$SRC_ICON" --out "$ICONSET_DIR/icon_16x16@2x.png"  2>/dev/null
    sips -z 32 32     "$SRC_ICON" --out "$ICONSET_DIR/icon_32x32.png"     2>/dev/null
    sips -z 64 64     "$SRC_ICON" --out "$ICONSET_DIR/icon_32x32@2x.png"  2>/dev/null
    sips -z 128 128   "$SRC_ICON" --out "$ICONSET_DIR/icon_128x128.png"   2>/dev/null
    sips -z 256 256   "$SRC_ICON" --out "$ICONSET_DIR/icon_128x128@2x.png" 2>/dev/null
    sips -z 256 256   "$SRC_ICON" --out "$ICONSET_DIR/icon_256x256.png"   2>/dev/null
    sips -z 512 512   "$SRC_ICON" --out "$ICONSET_DIR/icon_256x256@2x.png" 2>/dev/null
    sips -z 512 512   "$SRC_ICON" --out "$ICONSET_DIR/icon_512x512.png"   2>/dev/null
    sips -z 1024 1024 "$SRC_ICON" --out "$ICONSET_DIR/icon_512x512@2x.png" 2>/dev/null
    iconutil -c icns "$ICONSET_DIR" -o "$BUNDLE_DIR/Contents/Resources/icon.icns"
    echo "Icon converted to ICNS"
else
    echo "Warning: sips/iconutil not found, skipping icon conversion"
fi

echo ""
echo "Built: $BUNDLE_DIR"
echo "You can move it to /Applications or run it directly."
