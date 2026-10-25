#!/bin/zsh
# Run the test suite with a toolchain that works on both full Xcode and
# Command-Line-Tools-only installations.
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
PROJECT_DIR="${SCRIPT_DIR:h}"

EXTRA_FLAGS=()
TOOLCHAIN_DIR="$(xcode-select -p 2>/dev/null || true)"
TESTING_PLUGIN="${TOOLCHAIN_DIR}/usr/lib/swift/host/plugins/testing"

# CLT-only installations need the Swift Testing macro plugin to be passed
# explicitly; full Xcode discovers it automatically.
if [[ -n "${TOOLCHAIN_DIR}" && -d "${TESTING_PLUGIN}" ]]; then
  EXTRA_FLAGS+=(-Xswiftc -plugin-path -Xswiftc "${TESTING_PLUGIN}")
fi

cd "${PROJECT_DIR}"
exec swift test --disable-sandbox "${EXTRA_FLAGS[@]}" "$@"
