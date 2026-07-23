#!/usr/bin/env bash
#
# Download the latest Hayabusa release for this platform and extract it to ./hayabusa/
#
# Requires: curl, unzip. Uses the GitHub releases API to find the latest tag,
# then selects the release asset matching this OS/architecture.
#
set -euo pipefail

REPO="Yamato-Security/hayabusa"
DEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hayabusa"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Error: '$1' is required but not installed." >&2; exit 1; }; }
need curl
need unzip

# --- Detect platform -> Hayabusa asset keyword -------------------------------
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)  os_key="lin" ;;
  Darwin) os_key="mac" ;;
  *) echo "Error: unsupported OS '$os'. Download manually from https://github.com/${REPO}/releases" >&2; exit 1 ;;
esac

# Ordered list of arch keywords to try (naming has varied across releases).
case "$os_key:$arch" in
  lin:x86_64)            arch_keys=("x64-gnu" "x64") ;;
  lin:aarch64|lin:arm64) arch_keys=("arm64-gnu" "arm64") ;;
  mac:x86_64)            arch_keys=("mac-x64" "mac-intel" "x64") ;;
  mac:arm64|mac:aarch64) arch_keys=("mac-arm64" "mac-aarch64" "arm64") ;;
  *) echo "Error: unsupported architecture '$arch' on '$os'." >&2; exit 1 ;;
esac

# --- Find the matching asset URL --------------------------------------------
echo "Querying latest release of ${REPO}..."
release_json="$(curl -fsSL -H "Accept: application/vnd.github+json" "$API_URL")"

# All .zip asset URLs, excluding source bundles.
mapfile -t urls < <(
  printf '%s\n' "$release_json" \
    | grep -oE '"browser_download_url": *"[^"]+\.zip"' \
    | sed -E 's/.*"(https[^"]+)"/\1/' \
    | grep -viE 'all-sources|src'
)

asset_url=""
for key in "${arch_keys[@]}"; do
  for url in "${urls[@]}"; do
    if [[ "$url" == *"$os_key"* && "$url" == *"$key"* ]] || [[ "$url" == *"$key"* && "$os_key" == "mac" ]]; then
      asset_url="$url"; break 2
    fi
  done
done

if [[ -z "$asset_url" ]]; then
  echo "Error: could not find a release asset for ${os}/${arch}." >&2
  echo "Available assets:" >&2
  printf '  %s\n' "${urls[@]}" >&2
  exit 1
fi

echo "Selected asset: $(basename "$asset_url")"

# --- Download & extract ------------------------------------------------------
tmp_zip="$(mktemp --suffix=.zip)"
trap 'rm -f "$tmp_zip"' EXIT

echo "Downloading..."
curl -fSL --progress-bar "$asset_url" -o "$tmp_zip"

echo "Extracting to ${DEST_DIR}/ ..."
rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
unzip -q "$tmp_zip" -d "$DEST_DIR"

# Make the hayabusa binary executable (name includes version/platform).
bin="$(find "$DEST_DIR" -maxdepth 2 -type f -iname 'hayabusa*' ! -iname '*.zip' | head -n1 || true)"
if [[ -n "$bin" ]]; then
  chmod +x "$bin"
  echo "Hayabusa binary: $bin"
  echo "Version:"
  "$bin" --help >/dev/null 2>&1 && "$bin" --version 2>/dev/null || true
else
  echo "Warning: extracted archive but could not locate the hayabusa binary in ${DEST_DIR}." >&2
fi

echo "Done."
