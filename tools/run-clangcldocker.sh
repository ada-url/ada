#!/usr/bin/env bash
set -e
SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"
ROOT_PATH=$SCRIPT_PATH/..
ALL_ADA_FILES=$(cd "$ROOT_PATH" && git ls-tree --full-tree --name-only -r HEAD | grep -e ".*\.\(c\|h\|cc\|cpp\|hh\)\$" | grep -vFf clang-format-ignore.txt)

if clang-format-15 --version  2>/dev/null | grep -qF 'version 15.'; then
  cd "$ROOT_PATH"; clang-format-15 --style=file --verbose -i "$@" "$ALL_ADA_FILES"
  exit 0
elif clang-format --version  2>/dev/null | grep -qF 'version 15.'; then
  cd "$ROOT_PATH"; clang-format --style=file --verbose -i "$@" "$ALL_ADA_FILES"
  exit 0
fi
echo "Trying to use docker"
command -v docker >/dev/null 2>&1 || { echo >&2 "Please install docker. E.g., go to https://www.docker.com/products/docker-desktop Type 'docker' to diagnose the problem."; exit 1; }
docker info >/dev/null 2>&1 || { echo >&2 "Docker server is not running? type 'docker info'."; exit 1; }

if [ -t 0 ];
  then DOCKER_ARGS=-it;
fi

docker pull kszonek/clang-format-15

docker run --rm $DOCKER_ARGS \
  -v "$ROOT_PATH":"$ROOT_PATH":Z \
  -w "$ROOT_PATH" \
  -u "$(id -u "$USER"):$(id -g "$USER")" \
  kszonek/clang-format-15 \
  --style=file \
  --verbose \
  -i "$@" "$ALL_ADA_FILES"
