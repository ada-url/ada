#!/usr/bin/env bash
# Run clang-format and clang-tidy on first-party source files.
# Uses the locally installed LLVM 22 toolchain when available,
# falling back to the xianpengshen/clang-tools:22 Docker image.
#
# clang-tidy is run only on src/*.cpp (excluding third-party ada_idna.cpp).
# Headers under include/ada/ are analysed implicitly as they are included
# by those translation units.  Tests, benchmarks, singleheader, and all
# vendored dependencies are intentionally excluded.
#
# Usage: tools/run-clangcldocker.sh [extra clang-format flags...]
set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
MAINSOURCE="$SCRIPTPATH/.."
DOCKER_IMAGE=xianpengshen/clang-tools:22

ALL_ADA_FILES=$(cd "$MAINSOURCE" && \
  git ls-tree --full-tree --name-only -r HEAD | grep -E '.*\.(c|h|cc|cpp|hh)$')

# ada.cpp is the single translation unit that #includes every other .cpp file.
# Running clang-tidy on it covers all first-party code; HeaderFilterRegex in
# .clang-tidy controls which included files generate diagnostics.
TIDY_SRC=src/ada.cpp

# ── helpers ──────────────────────────────────────────────────────────────────

have_tool_version() {
  command -v "$1" >/dev/null 2>&1 && \
    "$1" --version 2>/dev/null | grep -qF 'version 22.'
}

require_docker() {
  command -v docker >/dev/null 2>&1 || {
    echo >&2 "docker not found. Install docker or the LLVM 22 toolchain."
    exit 1
  }
  docker info >/dev/null 2>&1 || {
    echo >&2 "Docker daemon is not running (try: docker info)."
    exit 1
  }
  docker pull -q "$DOCKER_IMAGE" >/dev/null
}

# Number of parallel jobs, with a sane fallback.
JOBS=$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)

# ── clang-format ─────────────────────────────────────────────────────────────
echo "=== clang-format ==="

# shellcheck disable=SC2086
if have_tool_version clang-format-22; then
  cd "$MAINSOURCE"
  clang-format-22 --style=file --verbose -i "$@" $ALL_ADA_FILES
elif have_tool_version clang-format; then
  cd "$MAINSOURCE"
  clang-format --style=file --verbose -i "$@" $ALL_ADA_FILES
else
  echo "clang-format 22 not found locally — using docker"
  require_docker
  it_flag=""
  [ -t 0 ] && it_flag="-it"
  # shellcheck disable=SC2086
  docker run --rm $it_flag \
    -v "$MAINSOURCE":"$MAINSOURCE":Z \
    -w "$MAINSOURCE" \
    -u "$(id -u):$(id -g)" \
    "$DOCKER_IMAGE" \
    clang-format --style=file --verbose -i "$@" $ALL_ADA_FILES
fi

# ── clang-tidy ────────────────────────────────────────────────────────────────
echo "=== clang-tidy ==="

# Generate compile_commands.json with clang++-22 and -stdlib=libc++ so that
# the compilation database exactly matches what CI uses.  CMAKE_CXX_CLANG_TIDY
# is intentionally NOT set here — we invoke clang-tidy manually below on only
# the first-party src/ files, keeping tests, benchmarks, singleheader, and
# vendored dependencies out of scope.
run_tidy() {
  local tidy="$1" cxx="$2"
  cd "$MAINSOURCE"
  rm -f build-clang-tidy/CMakeCache.txt
  CXX="$cxx" cmake -B build-clang-tidy \
    -DADA_USE_UNSAFE_STD_REGEX_PROVIDER=ON \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_CXX_FLAGS="-stdlib=libc++"
  "$tidy" -p build-clang-tidy "$TIDY_SRC"
}

if have_tool_version clang-tidy-22 && command -v clang++-22 >/dev/null 2>&1; then
  run_tidy clang-tidy-22 clang++-22
elif have_tool_version clang-tidy && command -v clang++ >/dev/null 2>&1; then
  run_tidy clang-tidy clang++
else
  echo "clang-tidy 22 not found locally — using docker"
  require_docker
  docker run --rm \
    -v "$MAINSOURCE":"$MAINSOURCE":Z \
    -w "$MAINSOURCE" \
    -e DEBIAN_FRONTEND=noninteractive \
    --entrypoint bash \
    "$DOCKER_IMAGE" -c "
      git config --global --add safe.directory '$MAINSOURCE' 2>/dev/null || true
      apt-get update -qq >/dev/null 2>&1
      apt-get install -y -qq --no-install-recommends \
        ca-certificates cmake ninja-build clang-22 \
        libc++-22-dev libc++abi-22-dev >/dev/null 2>&1
      rm -rf build-clang-tidy
      CC=clang-22 CXX=clang++-22 cmake -B build-clang-tidy -G Ninja \
        -DADA_USE_UNSAFE_STD_REGEX_PROVIDER=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_CXX_FLAGS='-stdlib=libc++'
      clang-tidy-22 -p build-clang-tidy "$TIDY_SRC"
    "
fi
