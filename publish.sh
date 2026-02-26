#!/bin/bash
set -euo pipefail

# Local build + publish script for Client Records (macOS Apple Silicon only)
# Usage: ./publish.sh <version>
# Example: ./publish.sh 1.0.8

REPO="therapytools/Client-Records"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TAURI_DIR="$SCRIPT_DIR/tauri-app"
KEY_PATH="$HOME/.tauri/client-records.key"
KEY_PASSWORD="tauri123"

# --- Validate input ---
if [ -z "${1:-}" ]; then
  echo "Usage: ./publish.sh <version>"
  echo "Example: ./publish.sh 1.0.8"
  exit 1
fi

VERSION="$1"
TAG="v$VERSION"

echo "==> Publishing Client Records $TAG"

# --- Check prerequisites ---
command -v gh >/dev/null 2>&1 || { echo "ERROR: gh CLI not installed. Run: brew install gh"; exit 1; }
command -v npx >/dev/null 2>&1 || { echo "ERROR: npx not found. Install Node.js first."; exit 1; }

if [ ! -f "$KEY_PATH" ]; then
  echo "ERROR: Signing key not found at $KEY_PATH"
  echo "Generate one with: npx tauri signer generate -w $KEY_PATH"
  exit 1
fi

# --- Update version in configs ---
echo "==> Updating version to $VERSION"
cd "$TAURI_DIR"
python3 -c "
import json
for f in ['src-tauri/tauri.conf.json', 'package.json']:
    with open(f) as fh: d = json.load(fh)
    d['version'] = '$VERSION'
    with open(f, 'w') as fh: json.dump(d, fh, indent=2)
    print(f'  Updated {f}')
"
# Update Cargo.toml version
sed -i '' "s/^version = \".*\"/version = \"$VERSION\"/" src-tauri/Cargo.toml
echo "  Updated src-tauri/Cargo.toml"

# --- Build ---
echo "==> Building Tauri app..."
export TAURI_SIGNING_PRIVATE_KEY=$(cat "$KEY_PATH")
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$KEY_PASSWORD"
npm run tauri build -- --bundles app

BUNDLE_DIR="src-tauri/target/release/bundle/macos"
APP_NAME="Client Records.app"
TARGZ="Client.Records_${VERSION}_aarch64.app.tar.gz"

# --- Create updater bundle ---
echo "==> Creating updater tar.gz..."
cd "$BUNDLE_DIR"
tar czf "$TARGZ" "$APP_NAME"

# --- Sign ---
echo "==> Signing bundle..."
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD
cd "$TAURI_DIR"
npx tauri signer sign -f "$KEY_PATH" -p "$KEY_PASSWORD" "$BUNDLE_DIR/$TARGZ"

SIG_FILE="$BUNDLE_DIR/${TARGZ}.sig"

# --- Git tag ---
echo "==> Creating git tag $TAG..."
cd "$SCRIPT_DIR"
git add -A
git diff --cached --quiet || git commit -m "Release $TAG"
git tag -f "$TAG"
git push origin main --tags

# --- Create GitHub release ---
echo "==> Creating GitHub release $TAG..."
gh release create "$TAG" \
  -R "$REPO" \
  --title "Client Records $TAG" \
  --notes "macOS (Apple Silicon) release." \
  "$TAURI_DIR/$BUNDLE_DIR/$TARGZ" \
  "$TAURI_DIR/$SIG_FILE" \
  2>/dev/null || {
    echo "  Release exists, uploading assets..."
    gh release upload "$TAG" -R "$REPO" --clobber \
      "$TAURI_DIR/$BUNDLE_DIR/$TARGZ" \
      "$TAURI_DIR/$SIG_FILE"
  }

# --- Generate and upload latest.json ---
echo "==> Generating latest.json..."
SIGNATURE=$(cat "$TAURI_DIR/$SIG_FILE")
BUNDLE_URL="https://github.com/$REPO/releases/download/$TAG/$TARGZ"

python3 -c "
import json, datetime
data = {
    'version': '$VERSION',
    'notes': 'macOS (Apple Silicon) release.',
    'pub_date': datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'platforms': {
        'darwin-aarch64': {
            'signature': '''$SIGNATURE''',
            'url': '$BUNDLE_URL'
        }
    }
}
with open('/tmp/latest.json', 'w') as f:
    json.dump(data, f, indent=2)
"

gh release upload "$TAG" /tmp/latest.json -R "$REPO" --clobber

echo ""
echo "==> Done! Published Client Records $TAG"
echo "    Release: https://github.com/$REPO/releases/tag/$TAG"
echo "    Updater: https://github.com/$REPO/releases/latest/download/latest.json"
