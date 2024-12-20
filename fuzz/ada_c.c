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
  
  if (!out) {
    return 0;
  }

  bool is_valid = ada_is_valid(out);
  
  if (!is_valid) {
    ada_free(out);
    return 0;
  }

  ada_set_href(out, (char*)data, size);
  ada_set_host(out, (char*)data, size);
  ada_set_hostname(out, (char*)data, size);
  ada_set_protocol(out, (char*)data, size);
  ada_set_username(out, (char*)data, size);
  ada_set_password(out, (char*)data, size);
  ada_set_port(out, (char*)data, size);
  ada_set_pathname(out, (char*)data, size);
  ada_set_search(out, (char*)data, size);
  ada_set_hash(out, (char*)data, size);

  ada_get_hash(out);
  ada_get_host(out);
  ada_get_host_type(out);
  ada_get_hostname(out);
  ada_get_href(out);

  ada_owned_string out_get_origin = ada_get_origin(out);
  
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

  ada_clear_port(out);
  ada_clear_hash(out);
  ada_clear_search(out);

  ada_free_owned_string(out_get_origin);

  bool can_parse_result = ada_can_parse((char*)data, size);

  ada_free(out);

  return 0;
}
