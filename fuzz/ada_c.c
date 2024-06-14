#include "ada_c.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  /**
   * ada_c
   */
  ada_url out = ada_parse((char*)data, size);
  bool is_valid = ada_is_valid(out);

  if (out) {
    ada_get_hash(out);
    ada_get_host(out);
    ada_get_host_type(out);
    ada_get_hostname(out);
    ada_get_href(out);
    ada_get_origin(out);
    ada_get_pathname(out);
    ada_get_username(out);
    ada_get_password(out);
    ada_get_protocol(out);
    ada_get_port(out);
    ada_get_search(out);
    ada_get_scheme_type(out);

    ada_has_credentials(out);
    ada_has_empty_hostname(out);
    ada_has_hostname(out);
    ada_has_non_empty_username(out);
    ada_has_non_empty_password(out);
    ada_has_port(out);
    ada_has_password(out);
    ada_has_hash(out);
    ada_has_search(out);

    ada_get_components(out);
  }

  bool can_parse_result = ada_can_parse((char*)data, size);

  return 0;
}
