#!/bin/zsh
# Run the test suite on full Xcode, Command-Line-Tools-only, and restricted
# developer sandboxes. Caches are kept under /tmp so they never touch user dirs.
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
PROJECT_DIR="${SCRIPT_DIR:h}"
TEST_TMP="/tmp/claudeguard-test-$(id -u)"

mkdir -p \
  "${TEST_TMP}/clang-module-cache" \
  "${TEST_TMP}/swiftpm-module-cache" \
  "${TEST_TMP}/swiftpm-cache" \
  "${TEST_TMP}/swiftpm-config" \
  "${TEST_TMP}/swiftpm-security"
export TMPDIR="${TEST_TMP}"
export CLANG_MODULE_CACHE_PATH="${TEST_TMP}/clang-module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="${TEST_TMP}/swiftpm-module-cache"

EXTRA_FLAGS=(
  --disable-sandbox
  --scratch-path "${TEST_TMP}/build"
  --cache-path "${TEST_TMP}/swiftpm-cache"
  --config-path "${TEST_TMP}/swiftpm-config"
  --security-path "${TEST_TMP}/swiftpm-security"
  -Xcc -fmodules-cache-path="${TEST_TMP}/clang-module-cache"
  -Xswiftc -module-cache-path -Xswiftc "${TEST_TMP}/swiftpm-module-cache"
)

TOOLCHAIN_DIR="$(xcode-select -p 2>/dev/null || true)"
TESTING_PLUGIN="${TOOLCHAIN_DIR}/usr/lib/swift/host/plugins/testing"
if [[ -n "${TOOLCHAIN_DIR}" && -d "${TESTING_PLUGIN}" ]]; then
  EXTRA_FLAGS+=(-Xswiftc -plugin-path -Xswiftc "${TESTING_PLUGIN}")
fi

cd "${PROJECT_DIR}"
exec swift test "${EXTRA_FLAGS[@]}" "$@"
