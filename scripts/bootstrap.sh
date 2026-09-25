#!/usr/bin/env bash
# Install the pinned scanners into ./.tools (repo-local, git-ignored) and verify their versions.
set -euo pipefail
cd "$(dirname "$0")/.."
source tools.lock
TOOLS="$PWD/.tools"
BIN="$TOOLS/bin"
mkdir -p "$BIN"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) TRIVY_OS=macOS-ARM64; CONFTEST_OS=Darwin_arm64 ;;
  Linux-x86_64) TRIVY_OS=Linux-64bit; CONFTEST_OS=Linux_x86_64 ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

# fetch_release <repo> <tag> <asset> <checksums-file> <binary>
fetch_release() {
  local repo=$1 tag=$2 asset=$3 sums=$4 binary=$5 tmp
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/$asset" "https://github.com/$repo/releases/download/$tag/$asset"
  curl -fsSL -o "$tmp/$sums" "https://github.com/$repo/releases/download/$tag/$sums"
  (cd "$tmp" && grep " $asset\$" "$sums" | shasum -a 256 -c -)
  tar -xzf "$tmp/$asset" -C "$tmp" "$binary"
  mv "$tmp/$binary" "$BIN/$binary"
  rm -rf "$tmp"
}

fetch_release aquasecurity/trivy "v$TRIVY_VERSION" "trivy_${TRIVY_VERSION}_${TRIVY_OS}.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" trivy
fetch_release open-policy-agent/conftest "v$CONFTEST_VERSION" "conftest_${CONFTEST_VERSION}_${CONFTEST_OS}.tar.gz" checksums.txt conftest

export UV_TOOL_DIR="$TOOLS/uv" UV_TOOL_BIN_DIR="$BIN"
uv tool install --force --quiet "semgrep==$SEMGREP_VERSION"
uv tool install --force --quiet --python "$CHECKOV_PYTHON" "checkov==$CHECKOV_VERSION"

# check <binary> <expected-version> <version-args...>
check() {
  local binary=$1 expected=$2; shift 2
  if ! "$BIN/$binary" "$@" 2>&1 | grep -q "$expected"; then
    echo "version mismatch: $binary is not $expected" >&2; exit 1
  fi
  echo "ok  $binary $expected"
}
check trivy "$TRIVY_VERSION" --version
check conftest "$CONFTEST_VERSION" --version
check semgrep "$SEMGREP_VERSION" --version
check checkov "$CHECKOV_VERSION" --version
