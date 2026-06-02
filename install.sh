#!/usr/bin/env bash
set -e

# Hardcoded ID from your Chrome environment
EXT_ID="ffdnoolignchomllpiibkiiommkaokgd"

# THIS IS THE CRITICAL CHANGE:
BINARY_PATH="$(pwd)/mor_native_bridge/run_bridge.sh"

MANIFEST_PATH="$(pwd)/mor_native_bridge/moribund.native.bridge.json"

echo "Building Rust bridge..."
cargo build --release --bin mor_native_bridge

echo "Writing JSON map..."
cat <<EOF > "$MANIFEST_PATH"
{
  "name": "moribund.native.bridge",
  "description": "Moribund LMS vault native messaging bridge",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXT_ID/"
  ]
}
EOF

echo "Symlinking to browser folders..."
for BROWSER in "google-chrome" "chromium" "BraveSoftware/Brave-Browser"; do
  DIR="$HOME/.config/$BROWSER/NativeMessagingHosts"
  mkdir -p "$DIR"
  ln -sf "$MANIFEST_PATH" "$DIR/moribund.native.bridge.json"
done

echo "Done. Moribund Sensor connected."