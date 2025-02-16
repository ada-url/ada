#!/bin/sh
set -e

TARGET_MODULE=$1
BASE_DIR=$(pwd)
WPT_DIR="$BASE_DIR/tests/wpt"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_module>"
    exit 1
fi

WORKSPACE=$(mktemp -d 2> /dev/null || mktemp -d -t 'tmp')

cleanup () {
  EXIT_CODE=$?
  [ -d "$WORKSPACE" ] && rm -rf "$WORKSPACE"
  exit $EXIT_CODE
}

trap cleanup INT TERM EXIT

cd "$WORKSPACE"
git clone \
  --no-checkout \
  --depth=1 \
  --filter=blob:none \
  --sparse \
  https://github.com/web-platform-tests/wpt.git wpt
cd wpt
# Conditionally sparse-checkout based on TARGET_MODULE
if [ "$TARGET_MODULE" = "url" ]; then
  git sparse-checkout add "url/resources"
elif [ "$TARGET_MODULE" = "urlpattern" ]; then
  git sparse-checkout add "urlpattern/resources"
else
  echo "Invalid target module: $TARGET_MODULE. Must be 'url' or 'urlpattern'."
  exit 1
fi

git checkout

# Copy the appropriate resources based on the target module
if [ "$TARGET_MODULE" = "url" ]; then
  cp url/resources/*.json "$WPT_DIR"
elif [ "$TARGET_MODULE" = "urlpattern" ]; then
  cp urlpattern/resources/*.json "$WPT_DIR"
fi
