#!/bin/sh
# Rename every setter except url_aggregator::set_password, then plant that
# one's alias check in the existing padding so the body does not move.
# Restarts from the pristine object so a second PRE_LINK is a no-op in effect.
set -eu
unity=$1
base=${unity}.base
username=_ZN3ada14url_aggregator12set_usernameESt17basic_string_viewIcSt11char_traitsIcEE

if nm -g --defined-only "$unity" | awk -v sym="$username" '$3 == sym { found = 1 } END { exit !found }'; then
  cp -f "$unity" "$base"
fi

if [ ! -f "$base" ]; then
  echo "rename_setter_symbols: missing pristine unity object" >&2
  exit 1
fi

cp -f "$base" "$unity"

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

python3 "${0%/*}/patch_password_alias.py" "$unity"
