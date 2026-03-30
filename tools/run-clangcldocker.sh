#!/usr/bin/env bash
# Run clang-format and clang-tidy on all tracked source files.
# Uses the locally installed LLVM 22 toolchain when available,
# falling back to the xianpengshen/clang-tools:22 Docker image.
#
# The Docker image has clang-format and clang-tidy but NOT cmake.
# When falling back to Docker for clang-tidy, compile_commands.json is
# generated on the host first (requires cmake), then clang-tidy is run
# inside the container against that compilation database.
#
# Usage: tools/run-clangcldocker.sh [extra clang-format flags...]
set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
MAINSOURCE="$SCRIPTPATH/.."
DOCKER_IMAGE=xianpengshen/clang-tools:22

ALL_ADA_FILES=$(cd "$MAINSOURCE" && \
  git ls-tree --full-tree --name-only -r HEAD | grep -E '.*\.(c|h|cc|cpp|hh)$')

# Source files that clang-tidy should check (excludes third-party code).
TIDY_CPP_FILES=$(cd "$MAINSOURCE" && \
  git ls-tree --full-tree --name-only -r HEAD | \
  grep -E '^src/.*\.cpp$' | grep -v 'ada_idna')

# ── helpers ──────────────────────────────────────────────────────────────────

have_tool_version() {
  # Returns 0 if $1 exists and reports "version 22." in its --version output.
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
  docker pull "$DOCKER_IMAGE"
}

docker_run() {
  local it_flag=""
  [ -t 0 ] && it_flag="-it"
  # shellcheck disable=SC2086
  docker run --rm $it_flag \
    -v "$MAINSOURCE":"$MAINSOURCE":Z \
    -w "$MAINSOURCE" \
    -u "$(id -u):$(id -g)" \
    "$DOCKER_IMAGE" "$@"
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
  # shellcheck disable=SC2086
  docker_run clang-format --style=file --verbose -i "$@" $ALL_ADA_FILES
fi

# ── clang-tidy ────────────────────────────────────────────────────────────────
echo "=== clang-tidy ==="

# Run cmake with CMAKE_CXX_CLANG_TIDY so that clang-tidy is invoked on every
# translation unit during the build.  A dedicated build directory is used so
# the user's normal build directory is left untouched.
run_tidy_cmake() {
  local tidy="$1" cxx="$2"
  cd "$MAINSOURCE"
  CXX="$cxx" cmake -B build-clang-tidy \
    -DADA_TESTING=ON \
    -DADA_USE_UNSAFE_STD_REGEX_PROVIDER=ON \
    -DCMAKE_CXX_CLANG_TIDY="$tidy" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_CXX_FLAGS="-stdlib=libc++"
  cmake --build build-clang-tidy -j"$JOBS"
}

# Generate compile_commands.json on the host using cmake.
# The xianpengshen/clang-tools Docker image has clang-tidy but not cmake, so
# we must produce the compilation database here before entering the container.
gen_compile_commands() {
  command -v cmake >/dev/null 2>&1 || {
    echo >&2 "cmake not found on the host. Install cmake to run clang-tidy."
    exit 1
  }
  cd "$MAINSOURCE"
  cmake -B build-clang-tidy \
    -DADA_TESTING=ON \
    -DADA_USE_UNSAFE_STD_REGEX_PROVIDER=ON \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_CXX_FLAGS="-stdlib=libc++"
}

if have_tool_version clang-tidy-22 && command -v clang++-22 >/dev/null 2>&1; then
  run_tidy_cmake clang-tidy-22 clang++-22
elif have_tool_version clang-tidy && command -v clang++ >/dev/null 2>&1; then
  run_tidy_cmake clang-tidy clang++
else
  echo "clang-tidy 22 not found locally — using docker"
  require_docker
  # Generate compile_commands.json on the host first.
  gen_compile_commands
  # Run clang-tidy inside the container using the compilation database.
  # The source tree is mounted at the same absolute path, so all paths in
  # compile_commands.json resolve correctly inside the container.
  # shellcheck disable=SC2086
  docker_run clang-tidy \
    -p "$MAINSOURCE/build-clang-tidy" \
    --warnings-as-errors='*' \
    $TIDY_CPP_FILES
fi
