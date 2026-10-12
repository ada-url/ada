#!/bin/sh
# Rename every setter except url_aggregator::set_password, then plant that
# one's alias check in the existing padding so the body does not move.
# When that prologue is not patchable, rename the body to the outline symbol
# and keep the weak definition in setter_alias.cpp (made global).
# Restarts from the pristine objects so a second PRE_LINK repeats cleanly.
set -eu
unity=$1
setter=$2
# full: tests need every setter checked. auto: keep the other setters in the
# unity object when the password patch applies, so a benchmark link does not
# pull the wrapper object.
mode=${3:-full}
cxx=${4:-c++}
base=${unity}.base
setter_base=${setter}.base
username=_ZN3ada14url_aggregator12set_usernameESt17basic_string_viewIcSt11char_traitsIcEE
password=_ZN3ada14url_aggregator12set_passwordESt17basic_string_viewIcSt11char_traitsIcEE
outline=_ZN3ada31outline_aggregator_set_passwordERNS_14url_aggregatorESt17basic_string_viewIcSt11char_traitsIcEE

# A freshly compiled unity object still defines set_username and does not
# reference the password alias. A patched one does, so it must not replace
# the pristine copy. Full mode renames set_username away and keeps this base.
if nm -g --defined-only "$unity" | awk -v sym="$username" '$3 == sym { found = 1 } END { exit !found }'; then
  if ! nm -u "$unity" | awk '$NF == "ada_agg_set_password_alias" { found = 1 } END { exit !found }'; then
    cp -f "$unity" "$base"
  fi
fi

if [ ! -f "$base" ]; then
  echo "rename_setter_symbols: missing pristine unity object" >&2
  exit 1
fi

if nm -g --defined-only "$setter" | awk -v sym="$password" '$2 == "W" && $3 == sym { found = 1 } END { exit !found }'; then
  cp -f "$setter" "$setter_base"
fi

if [ ! -f "$setter_base" ]; then
  echo "rename_setter_symbols: missing pristine setter object" >&2
  exit 1
fi

cp -f "$base" "$unity"
cp -f "$setter_base" "$setter"

rename_five() {
objcopy \
  --redefine-sym "_ZN3ada14url_aggregator12set_usernameESt17basic_string_viewIcSt11char_traitsIcEE=_ZN3ada31outline_aggregator_set_usernameERNS_14url_aggregatorESt17basic_string_viewIcSt11char_traitsIcEE" \
  --redefine-sym "_ZN3ada14url_aggregator12set_pathnameESt17basic_string_viewIcSt11char_traitsIcEE=_ZN3ada31outline_aggregator_set_pathnameERNS_14url_aggregatorESt17basic_string_viewIcSt11char_traitsIcEE" \
  --redefine-sym "_ZN3ada3url12set_usernameESt17basic_string_viewIcSt11char_traitsIcEE=_ZN3ada24outline_url_set_usernameERNS_3urlESt17basic_string_viewIcSt11char_traitsIcEE" \
  --redefine-sym "_ZN3ada3url12set_passwordESt17basic_string_viewIcSt11char_traitsIcEE=_ZN3ada24outline_url_set_passwordERNS_3urlESt17basic_string_viewIcSt11char_traitsIcEE" \
  --redefine-sym "_ZN3ada3url12set_pathnameESt17basic_string_viewIcSt11char_traitsIcEE=_ZN3ada24outline_url_set_pathnameERNS_3urlESt17basic_string_viewIcSt11char_traitsIcEE" \
  --redefine-sym "ada_set_username=ada_set_username_unity" --localize-symbol \
  ada_set_username_unity \
  --redefine-sym "ada_set_password=ada_set_password_unity" --localize-symbol \
  ada_set_password_unity \
  --redefine-sym "ada_set_pathname=ada_set_pathname_unity" --localize-symbol \
  ada_set_pathname_unity \
  "$unity"
}

if [ "$mode" = "full" ]; then
  rename_five
fi

status=0
if ! command -v python3 >/dev/null 2>&1; then
  status=2
elif python3 "${0%/*}/patch_password_alias.py" "$unity"; then
  status=0
else
  status=$?
fi

if [ "$status" -eq 2 ]; then
  if [ "$mode" != "full" ]; then
    rename_five
  fi
  objcopy --redefine-sym "${password}=${outline}" "$unity"
  if nm -g --defined-only "$unity" | awk -v sym="$password" '$3 == sym { found = 1 } END { exit !found }'; then
    echo "rename_setter_symbols: set_password was not renamed" >&2
    exit 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 "${0%/*}/patch_password_alias.py" --strengthen "$setter" "$password"
  fi
elif [ "$status" -ne 0 ]; then
  exit "$status"
elif [ "$mode" != "full" ]; then
  printf 'static int ada_setter_alias_unused;\n' | "$cxx" -c -x c - -o "$setter"
fi
