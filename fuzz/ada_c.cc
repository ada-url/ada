// C API fuzzer (C++ amalgamation; do not include ada_c.h — types come from
// ada_c.cpp in the amalgamation).

#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "ada.cpp"
#include "ada.h"

static std::string make_url_candidate(FuzzedDataProvider& fdp) {
  static constexpr const char* kSchemes[] = {
      "http://", "https://", "ws://",  "wss://", "ftp://",
      "file://", "HTTP://",  "https:", "http:",
  };
  static constexpr const char* kHosts[] = {
      "example.com",
      "www.example.com",
      "localhost",
      "127.0.0.1",
      "192.168.0.1",
      "0x7f.1",
      "[::1]",
      "xn--nxasmq6b.com",
      "user:pass@example.com",
      "example.com:8080",
      "a",
  };
  static constexpr const char* kRest[] = {
      "",           "/",           "/path",       "/path?q=1",
      "/path#frag", "/a/./b/../c", "/foo/%2e%2e", "?q=1",
      "#f",
  };
  std::string out;
  out += kSchemes[fdp.ConsumeIntegralInRange<size_t>(
      0, sizeof(kSchemes) / sizeof(kSchemes[0]) - 1)];
  out += kHosts[fdp.ConsumeIntegralInRange<size_t>(
      0, sizeof(kHosts) / sizeof(kHosts[0]) - 1)];
  out += kRest[fdp.ConsumeIntegralInRange<size_t>(
      0, sizeof(kRest) / sizeof(kRest[0]) - 1)];
  if (fdp.ConsumeBool() && !out.empty()) {
    std::string mid = fdp.ConsumeRandomLengthString(24);
    size_t pos = fdp.ConsumeIntegralInRange<size_t>(0, out.size());
    out.insert(pos, mid);
  }
  return out;
}

static void exercise_valid_url(ada_url out, const char* input, size_t input_len,
                               const char* other, size_t other_len) {
  if (!ada_is_valid(out)) return;

  ada_set_href(out, input, input_len);
  ada_set_host(out, other, other_len);
  ada_set_hostname(out, other, other_len);
  ada_set_protocol(out, other, other_len);
  ada_set_username(out, other, other_len);
  ada_set_password(out, other, other_len);
  ada_set_port(out, other, other_len);
  ada_set_pathname(out, other, other_len);
  ada_set_search(out, other, other_len);
  ada_set_hash(out, other, other_len);

  ada_get_hash(out);
  ada_get_host(out);
  uint8_t host_type = ada_get_host_type(out);
  if (host_type > 2) {
    printf("ada_get_host_type out of range: %u\n", (unsigned)host_type);
    abort();
  }
  ada_get_hostname(out);
  ada_string href = ada_get_href(out);
  ada_owned_string origin = ada_get_origin(out);
  ada_get_pathname(out);
  ada_get_username(out);
  ada_get_password(out);
  ada_get_protocol(out);
  ada_get_port(out);
  ada_get_search(out);

  uint8_t scheme_type = ada_get_scheme_type(out);
  if (scheme_type > 6) {
    printf("ada_get_scheme_type out of range: %u\n", (unsigned)scheme_type);
    abort();
  }

  ada_has_credentials(out);
  ada_has_empty_hostname(out);
  ada_has_hostname(out);
  ada_has_non_empty_username(out);
  ada_has_non_empty_password(out);
  ada_has_port(out);
  ada_has_password(out);
  ada_has_hash(out);
  ada_has_search(out);

  const ada_url_components* comps = ada_get_components(out);
  constexpr uint32_t kOmitted = 0xffffffffu;
  auto check_off = [&](uint32_t off, const char* name) {
    if (off != kOmitted && off > href.length) {
      printf("component %s out of bounds\n", name);
      abort();
    }
  };
  check_off(comps->protocol_end, "protocol_end");
  check_off(comps->username_end, "username_end");
  check_off(comps->host_start, "host_start");
  check_off(comps->host_end, "host_end");
  check_off(comps->pathname_start, "pathname_start");
  check_off(comps->search_start, "search_start");
  check_off(comps->hash_start, "hash_start");

  ada_clear_port(out);
  ada_clear_hash(out);
  ada_clear_search(out);
  ada_free_owned_string(origin);

  ada_url out_copy = ada_copy(out);
  if (ada_is_valid(out_copy)) {
    ada_get_href(out_copy);
  }
  ada_free(out_copy);

  ada_string final_href = ada_get_href(out);
  ada_url reparsed = ada_parse(final_href.data, final_href.length);
  if (!ada_is_valid(reparsed)) {
    printf("C API re-parse failed: %.*s\n", (int)final_href.length,
           final_href.data);
    ada_free(reparsed);
    abort();
  }
  ada_string reparsed_href = ada_get_href(reparsed);
  if (reparsed_href.length != final_href.length ||
      memcmp(reparsed_href.data, final_href.data, final_href.length) != 0) {
    printf("C API href idempotency failure\n");
    ada_free(reparsed);
    abort();
  }
  ada_free(reparsed);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  std::string primary = fdp.ConsumeBool() ? make_url_candidate(fdp)
                                          : fdp.ConsumeRandomLengthString(256);
  std::string secondary = fdp.ConsumeBool()
                              ? make_url_candidate(fdp)
                              : fdp.ConsumeRandomLengthString(256);

  const char* input = primary.data();
  size_t input_len = primary.size();
  const char* base = secondary.data();
  size_t base_len = secondary.size();

  ada_url out = ada_parse(input, input_len);
  bool is_valid = ada_is_valid(out);
  bool can_parse_result = ada_can_parse(input, input_len);
  if (can_parse_result != is_valid) {
    printf("ada_can_parse vs ada_parse disagreement\n");
    ada_free(out);
    abort();
  }
  exercise_valid_url(out, input, input_len, base, base_len);
  ada_free(out);

  ada_url out_with_base = ada_parse_with_base(input, input_len, base, base_len);
  bool with_base_valid = ada_is_valid(out_with_base);
  bool can_parse_with_base =
      ada_can_parse_with_base(input, input_len, base, base_len);
  if (can_parse_with_base != with_base_valid) {
    printf("ada_can_parse_with_base vs ada_parse_with_base disagreement\n");
    ada_free(out_with_base);
    abort();
  }
  if (with_base_valid) {
    ada_get_href(out_with_base);
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
  ada_free(out_with_base);

  {
    ada_owned_string unicode_result = ada_idna_to_unicode(input, input_len);
    ada_free_owned_string(unicode_result);
    ada_owned_string ascii_result = ada_idna_to_ascii(input, input_len);
    ada_free_owned_string(ascii_result);
  }

  {
    const char* version = ada_get_version();
    if (version == nullptr) {
      abort();
    }
    (void)strlen(version);
    (void)ada_get_version_components().major;
  }

  {
    ada_url_search_params sp = ada_parse_search_params(input, input_len);
    (void)ada_search_params_size(sp);
    ada_search_params_append(sp, input, input_len, base, base_len);
    ada_search_params_set(sp, input, input_len, base, base_len);
    (void)ada_search_params_has(sp, input, input_len);
    (void)ada_search_params_has_value(sp, input, input_len, base, base_len);
    (void)ada_search_params_get(sp, input, input_len).length;
    ada_strings all_vals = ada_search_params_get_all(sp, input, input_len);
    size_t all_size = ada_strings_size(all_vals);
    for (size_t i = 0; i < all_size; i++) {
      (void)ada_strings_get(all_vals, i).length;
    }
    ada_free_strings(all_vals);
    ada_search_params_sort(sp);
    ada_owned_string sp_str = ada_search_params_to_string(sp);
    ada_free_owned_string(sp_str);

    ada_url_search_params_keys_iter keys = ada_search_params_get_keys(sp);
    while (ada_search_params_keys_iter_has_next(keys)) {
      (void)ada_search_params_keys_iter_next(keys).length;
    }
    ada_free_search_params_keys_iter(keys);

    ada_url_search_params_values_iter vals = ada_search_params_get_values(sp);
    while (ada_search_params_values_iter_has_next(vals)) {
      (void)ada_search_params_values_iter_next(vals).length;
    }
    ada_free_search_params_values_iter(vals);

    ada_url_search_params_entries_iter ents = ada_search_params_get_entries(sp);
    while (ada_search_params_entries_iter_has_next(ents)) {
      ada_string_pair e = ada_search_params_entries_iter_next(ents);
      (void)e.key.length;
      (void)e.value.length;
    }
    ada_free_search_params_entries_iter(ents);

    ada_search_params_remove(sp, input, input_len);
    ada_search_params_remove_value(sp, input, input_len, base, base_len);
    ada_search_params_reset(sp, base, base_len);
    ada_free_search_params(sp);
  }

  static constexpr const char* kAnchors[] = {
      "https://example.com/",
      "http://127.0.0.1/x",
      "https://user:pass@host:8080/p?q=1#f",
      "file:///tmp/x",
  };
  for (const char* a : kAnchors) {
    size_t n = strlen(a);
    ada_url u = ada_parse(a, n);
    if (ada_is_valid(u) != ada_can_parse(a, n)) {
      ada_free(u);
      abort();
    }
    exercise_valid_url(u, a, n, "x", 1);
    ada_free(u);
  }

  return 0;
}
