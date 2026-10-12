#!/bin/sh
# Publish the uninstrumented setter bodies under outline_* names, then append
# the wrapper object to the end of the unity object. Appending keeps the
# existing functions at the same offsets, so GCC's setter codegen stays
# identical to main. Skip when this object was already rewritten and the
# wrapper object is empty (a relink without a recompile).
set -eu
unity=$1
wrap=$2
base=${unity}.base
orig=_ZN3ada14url_aggregator12set_passwordESt17basic_string_viewIcSt11char_traitsIcEE

has_sym() {
  nm -g --defined-only "$1" | awk -v sym="$2" '$3 == sym { found = 1 } END { exit !found }'
}

if has_sym "$unity" "$orig"; then
  cp -f "$unity" "$base"
fi

if [ ! -f "$base" ]; then
  echo "rename_setter_symbols: missing pristine unity object" >&2
  exit 1
fi

if ! has_sym "$wrap" "$orig"; then
  # Wrapper object has no public setter (already consumed, or not built).
  exit 0
fi

cp -f "$base" "$unity"

objcopy \
  --redefine-sym "_ZN3ada14url_aggregator12set_usernameESt17basic_string_viewIcSt11char_traitsIcEE=_ZN3ada31outline_aggregator_set_usernameERNS_14url_aggregatorESt17basic_string_viewIcSt11char_traitsIcEE" \
  --redefine-sym "_ZN3ada14url_aggregator12set_passwordESt17basic_string_viewIcSt11char_traitsIcEE=_ZN3ada31outline_aggregator_set_passwordERNS_14url_aggregatorESt17basic_string_viewIcSt11char_traitsIcEE" \
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

ld -r -o "${unity}.merged" "$unity" "$wrap"
mv -f "${unity}.merged" "$unity"
