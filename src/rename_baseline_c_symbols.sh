#!/bin/sh
# Hide the baseline C API symbols inside the unity object so the separate
# translation unit's definitions are the ones that get exported. Weak C++
# symbols (for example std::string::_M_replace) are left alone: the unity
# object is linked first and its copy must win.
set -eu
unity=$1
fixed=$2

if ! nm -g --defined-only "$unity" | awk '$3 == "ada_parse" { found = 1 } END { exit !found }'; then
  exit 0
fi

unity_syms=$(mktemp)
fixed_syms=$(mktemp)
trap 'rm -f "$unity_syms" "$fixed_syms"' EXIT

nm -g --defined-only "$unity" | awk '$2 ~ /^[TDRB]$/ { print $3 }' | LC_ALL=C sort >"$unity_syms"
nm -g --defined-only "$fixed" | awk '$2 ~ /^[TDRB]$/ { print $3 }' | LC_ALL=C sort >"$fixed_syms"

set --
while IFS= read -r sym; do
  set -- "$@" --redefine-sym "${sym}=${sym}_baseline" --localize-symbol "${sym}_baseline"
done <<EOF
$(LC_ALL=C comm -12 "$unity_syms" "$fixed_syms")
EOF

if [ "$#" -eq 0 ]; then
  echo "rename_baseline_c_symbols: no colliding strong symbols" >&2
  exit 1
fi

objcopy "$@" "$unity"
