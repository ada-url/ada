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
git clone --depth=1 --single-branch git@github.com:web-platform-tests/wpt.git wpt
rm -rf "$WPT_DIR"
mv "$WORKSPACE/wpt/url/resources" "$WPT_DIR"
