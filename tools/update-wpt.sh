#!/bin/sh
set -e

BASE_DIR=$(pwd)
WPT_DIR="$BASE_DIR/tests/wpt"

WORKSPACE=$(mktemp -d 2> /dev/null || mktemp -d -t 'tmp')

cleanup () {
  EXIT_CODE=$?
  [ -d "$WORKSPACE" ] && rm -rf "$WORKSPACE"
  exit $EXIT_CODE
}

trap cleanup INT TERM EXIT

cd "$WORKSPACE"
git clone \
  --depth=1 \
  --filter=blob:none \
  --sparse \
  https://github.com/web-platform-tests/wpt.git wpt
cd wpt
git sparse-checkout set "url/resources"
cp url/resources/*.json "$WPT_DIR"
