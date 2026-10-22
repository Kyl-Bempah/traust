#!/usr/bin/env bash
# Build the toolchain image from pinned scanner and Python dependencies.
#
# Usage:
#   ./scripts/build-toolchain-image.sh
#   ./scripts/build-toolchain-image.sh --tag myregistry/harness-toolchain:v0.331
#   ./scripts/build-toolchain-image.sh --no-db    # skip DB population (faster builds)
#
# Scanner versions come from config/external-tools.yaml; Python package SHAs
# come from pyproject.toml. Never edit Containerfile scanner ARGs directly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TAG="harness-toolchain:latest"
EXTRA_ARGS=""

for arg in "$@"; do
  case "$arg" in
    --tag=*) TAG="${arg#--tag=}" ;;
    --tag)   shift; TAG="$1" ;;
    --no-db) EXTRA_ARGS="$EXTRA_ARGS --build-arg SKIP_DB=1" ;;
  esac
done

BUILD_ARGS=$(python3 "$SCRIPT_DIR/containerfile-build-args.py")

# --- Pre-build Python wheels from pinned Git sources ---
WHEEL_DIR="$REPO_ROOT/_build/wheels"
rm -rf "$WHEEL_DIR"
mkdir -p "$WHEEL_DIR"

echo "Building pinned Python wheels into _build/wheels/ ..."
python3 "$SCRIPT_DIR/build-pinned-wheels.py" "$WHEEL_DIR"
python3 -m pip wheel --no-deps --wheel-dir "$WHEEL_DIR" "$REPO_ROOT" 2>&1 | tail -1
echo ""

echo "Building $TAG from configured pins..."
echo "  $BUILD_ARGS"
echo ""

# shellcheck disable=SC2086
podman build -f "$REPO_ROOT/Containerfile.toolchain" \
  $BUILD_ARGS \
  $EXTRA_ARGS \
  -t "$TAG" \
  "$REPO_ROOT"

# Clean up build artifacts
rm -rf "$REPO_ROOT/_build"

echo ""
echo "Built: $TAG"
echo "Verify: podman run --rm $TAG doctor --profile secure-code-audit"
