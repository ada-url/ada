#!/bin/sh
# Publish the uninstrumented setter bodies under outline_* names. The public
# symbols are defined in setter_alias.cpp. Skip when the object was already
# rewritten (PRE_LINK runs again on a relink).
set -eu
unity=$1

if ! nm -g --defined-only "$unity" | awk '$3 == "_ZN3ada14url_aggregator12set_passwordESt17basic_string_viewIcSt11char_traitsIcEE" { found = 1 } END { exit !found }'; then
  exit 0
fi

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
