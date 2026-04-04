#!/bin/bash
set -e

APP_NAME="TG WS Proxy"
BINARY_NAME="proxy-app"
BUNDLE_DIR="${APP_NAME}.app"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_ICON="$PROJECT_DIR/assets/icon.png"

cd "$PROJECT_DIR"

# ── 1. Build universal binary (arm64 + x86_64) ───────────────────────

echo "==> Building aarch64 (Apple Silicon)..."
cargo build --target aarch64-apple-darwin --release -p proxy-app

echo "==> Building x86_64 (Intel)..."
cargo build --target x86_64-apple-darwin --release -p proxy-app

echo "==> Creating universal binary..."
mkdir -p target/universal/release
lipo -create \
    -output "target/universal/release/$BINARY_NAME" \
    "target/aarch64-apple-darwin/release/$BINARY_NAME" \
    "target/x86_64-apple-darwin/release/$BINARY_NAME"

file "target/universal/release/$BINARY_NAME"

# ── 2. Create .app bundle ────────────────────────────────────────────

cd "$SCRIPT_DIR"
rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR/Contents/MacOS"
mkdir -p "$BUNDLE_DIR/Contents/Resources"

cp "$PROJECT_DIR/target/universal/release/$BINARY_NAME" "$BUNDLE_DIR/Contents/MacOS/"
cp "$SCRIPT_DIR/Info.plist" "$BUNDLE_DIR/Contents/"
echo "APPL????" > "$BUNDLE_DIR/Contents/PkgInfo"

# ── 3. Convert PNG → ICNS ────────────────────────────────────────────

if command -v sips &>/dev/null && command -v iconutil &>/dev/null; then
    ICONSET_DIR="$(mktemp -d)/icon.iconset"
    mkdir -p "$ICONSET_DIR"
    sips -z 16 16     "$SRC_ICON" --out "$ICONSET_DIR/icon_16x16.png"      2>/dev/null
    sips -z 32 32     "$SRC_ICON" --out "$ICONSET_DIR/icon_16x16@2x.png"   2>/dev/null
    sips -z 32 32     "$SRC_ICON" --out "$ICONSET_DIR/icon_32x32.png"      2>/dev/null
    sips -z 64 64     "$SRC_ICON" --out "$ICONSET_DIR/icon_32x32@2x.png"   2>/dev/null
    sips -z 128 128   "$SRC_ICON" --out "$ICONSET_DIR/icon_128x128.png"    2>/dev/null
    sips -z 256 256   "$SRC_ICON" --out "$ICONSET_DIR/icon_128x128@2x.png" 2>/dev/null
    sips -z 256 256   "$SRC_ICON" --out "$ICONSET_DIR/icon_256x256.png"    2>/dev/null
    sips -z 512 512   "$SRC_ICON" --out "$ICONSET_DIR/icon_256x256@2x.png" 2>/dev/null
    sips -z 512 512   "$SRC_ICON" --out "$ICONSET_DIR/icon_512x512.png"    2>/dev/null
    sips -z 1024 1024 "$SRC_ICON" --out "$ICONSET_DIR/icon_512x512@2x.png" 2>/dev/null
    iconutil -c icns "$ICONSET_DIR" -o "$BUNDLE_DIR/Contents/Resources/icon.icns"
    echo "==> Icon converted to ICNS"
else
    echo "Warning: sips/iconutil not found, skipping icon conversion"
fi

# ── 4. Create .dmg ───────────────────────────────────────────────────

if command -v create-dmg &>/dev/null; then
    echo "==> Creating DMG..."
    rm -f "${APP_NAME}"*.dmg
    create-dmg "$BUNDLE_DIR" || true
    echo ""
    ls -lh "${APP_NAME}"*.dmg 2>/dev/null
else
    echo ""
    echo "Tip: install create-dmg to build a DMG installer:"
    echo "  npm install -g create-dmg"
    echo "  # or: brew install create-dmg"
fi

echo ""
echo "Done: $BUNDLE_DIR"
echo "Move to /Applications or run directly."
