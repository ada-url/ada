#include "ada_c.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;

  /**
   * Split input: use first half as URL input, second half as base URL
   */
  size_t half = size / 2;
  const char* input = (const char*)data;
  size_t input_len = half;
  const char* base = (const char*)(data + half);
  size_t base_len = size - half;

  /**
   * ada_parse and ada_can_parse
   */
  ada_url out = ada_parse(input, input_len);
  bool is_valid = ada_is_valid(out);

  if (is_valid) {
    ada_set_href(out, input, input_len);
    ada_set_host(out, input, input_len);
    ada_set_hostname(out, input, input_len);
    ada_set_protocol(out, input, input_len);
    ada_set_username(out, input, input_len);
    ada_set_password(out, input, input_len);
    ada_set_port(out, input, input_len);
    ada_set_pathname(out, input, input_len);
    ada_set_search(out, input, input_len);
    ada_set_hash(out, input, input_len);

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

    /* Test ada_copy */
    ada_url out_copy = ada_copy(out);
    bool copy_is_valid = ada_is_valid(out_copy);
    if (copy_is_valid) {
      ada_string href_orig = ada_get_href(out);
      ada_string href_copy = ada_get_href(out_copy);
      /* The copy should have the same href (after our setters above) */
      (void)href_orig;
      (void)href_copy;
    }
    ada_free(out_copy);
  }

  bool can_parse_result = ada_can_parse(input, input_len);
  (void)can_parse_result;

  ada_free(out);

  /**
   * ada_parse_with_base and ada_can_parse_with_base
   */
  ada_url out_with_base = ada_parse_with_base(input, input_len, base, base_len);
  bool with_base_valid = ada_is_valid(out_with_base);

  if (with_base_valid) {
    ada_string href = ada_get_href(out_with_base);
    volatile size_t len = href.length;
    (void)len;

    ada_owned_string origin = ada_get_origin(out_with_base);
    ada_free_owned_string(origin);

    ada_get_hostname(out_with_base);
    ada_get_pathname(out_with_base);
    ada_get_search(out_with_base);
    ada_get_hash(out_with_base);
    ada_get_protocol(out_with_base);
    ada_get_port(out_with_base);
    ada_get_username(out_with_base);
    ada_get_password(out_with_base);

    ada_has_credentials(out_with_base);
    ada_has_port(out_with_base);
    ada_has_hash(out_with_base);
    ada_has_search(out_with_base);
    ada_get_components(out_with_base);
  }

  bool can_parse_with_base =
      ada_can_parse_with_base(input, input_len, base, base_len);

  /* Consistency check: can_parse_with_base should match
   * ada_is_valid(ada_parse_with_base(...)) */
  if (can_parse_with_base != with_base_valid) {
    printf(
        "ada_can_parse_with_base inconsistency: can_parse=%d is_valid=%d\n",
        can_parse_with_base, with_base_valid);
    abort();
  }

  ada_free(out_with_base);

  /**
   * IDNA C API
   */
  {
    ada_owned_string unicode_result = ada_idna_to_unicode(input, input_len);
    volatile size_t ulen = unicode_result.length;
    (void)ulen;
    ada_free_owned_string(unicode_result);

    ada_owned_string ascii_result = ada_idna_to_ascii(input, input_len);
    volatile size_t alen = ascii_result.length;
    (void)alen;
    ada_free_owned_string(ascii_result);
  }

  /**
   * Version API
   */
  {
    const char* version = ada_get_version();
    volatile size_t vlen = strlen(version);
    (void)vlen;

    ada_version_components ver_comps = ada_get_version_components();
    volatile int major = ver_comps.major;
    (void)major;
  }

  /**
   * Search params C API - comprehensive coverage
   */
  {
    ada_url_search_params sp = ada_parse_search_params(input, input_len);

    /* Size */
    volatile size_t sp_size = ada_search_params_size(sp);
    (void)sp_size;

    /* Append */
    ada_search_params_append(sp, input, input_len, base, base_len);

    /* Set (replaces first match) */
    ada_search_params_set(sp, input, input_len, base, base_len);

    /* has */
    volatile bool has_key = ada_search_params_has(sp, input, input_len);
    (void)has_key;

    /* has_value */
    volatile bool has_kv =
        ada_search_params_has_value(sp, input, input_len, base, base_len);
    (void)has_kv;

    /* get - returns ada_string (may have data=NULL if not found) */
    ada_string got = ada_search_params_get(sp, input, input_len);
    volatile size_t got_len = got.length;
    (void)got_len;

    /* get_all */
    ada_strings all_vals =
        ada_search_params_get_all(sp, input, input_len);
    volatile size_t all_size = ada_strings_size(all_vals);
    for (size_t i = 0; i < all_size; i++) {
      ada_string s = ada_strings_get(all_vals, i);
      volatile size_t slen = s.length;
      (void)slen;
    }
    ada_free_strings(all_vals);

    /* sort */
    ada_search_params_sort(sp);

    /* to_string */
    ada_owned_string sp_str = ada_search_params_to_string(sp);
    volatile size_t str_len = sp_str.length;
    (void)str_len;
    ada_free_owned_string(sp_str);

    /* keys iterator */
    ada_url_search_params_keys_iter keys_iter =
        ada_search_params_get_keys(sp);
    while (ada_search_params_keys_iter_has_next(keys_iter)) {
      ada_string k = ada_search_params_keys_iter_next(keys_iter);
      volatile size_t klen = k.length;
      (void)klen;
    }
    ada_free_search_params_keys_iter(keys_iter);

    /* values iterator */
    ada_url_search_params_values_iter values_iter =
        ada_search_params_get_values(sp);
    while (ada_search_params_values_iter_has_next(values_iter)) {
      ada_string v = ada_search_params_values_iter_next(values_iter);
      volatile size_t vlen = v.length;
      (void)vlen;
    }
    ada_free_search_params_values_iter(values_iter);

    /* entries iterator */
    ada_url_search_params_entries_iter entries_iter =
        ada_search_params_get_entries(sp);
    while (ada_search_params_entries_iter_has_next(entries_iter)) {
      ada_string_pair entry = ada_search_params_entries_iter_next(entries_iter);
      volatile size_t ek = entry.key.length;
      volatile size_t ev = entry.value.length;
      (void)ek;
      (void)ev;
    }
    ada_free_search_params_entries_iter(entries_iter);

    /* remove */
    ada_search_params_remove(sp, input, input_len);

    /* remove_value */
    ada_search_params_remove_value(sp, input, input_len, base, base_len);

    /* reset */
    ada_search_params_reset(sp, base, base_len);

    /* Verify size after reset */
    volatile size_t sp_size_after = ada_search_params_size(sp);
    (void)sp_size_after;

    ada_free_search_params(sp);
  }

  return 0;
}
