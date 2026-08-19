#!/usr/bin/env bash
# Install the pinned Atlas, and refuse anything whose bytes are not the ones this repository froze.
#
# The order here is the whole point: download to a temp file, verify, and only then make it
# executable and move it into place. Marking a downloaded blob executable before checking it means
# the check is advisory — the bytes are already on disk, already runnable, and a `chmod` that
# happened first is one careless `&&` away from being run.
#
# Usage: install-atlas.sh <version> <destination-directory>

set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:?usage: install-atlas.sh <version> <dest-dir>}"
dest="${2:?usage: install-atlas.sh <version> <dest-dir>}"
sums=scripts/atlas.sums

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64)        arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
esac
artifact="atlas-${os}-${arch}-${version}"

# An unlisted platform is a refusal, not a skip. "Verify if we happen to have a checksum" is a
# verification step that any new runner architecture silently turns off.
want=$(awk -v a="$artifact" '$2 == a {print $1}' "$sums")
if [ -z "$want" ]; then
  echo "FATAL: no pinned sha256 for $artifact in $sums." >&2
  echo "Add one (see the header of that file) rather than installing an unverified binary." >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/atlas" \
  "https://release.ariga.io/atlas/${artifact}"

got=$(shasum -a 256 "$tmp/atlas" | awk '{print $1}')
if [ "$got" != "$want" ]; then
  echo "FATAL: $artifact does not match the sha256 pinned in $sums." >&2
  echo "  expected $want" >&2
  echo "  got      $got" >&2
  echo >&2
  echo "The bytes behind this version changed. Do not work around this by refreshing the pin:" >&2
  echo "GEN001 trusts whatever this binary says, so an unexplained change is the thing to chase." >&2
  exit 1
fi

mkdir -p "$dest"
chmod +x "$tmp/atlas"
mv "$tmp/atlas" "$dest/atlas"
echo "installed atlas $version ($artifact, sha256 verified) into $dest"
