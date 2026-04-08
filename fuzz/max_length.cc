#include <fuzzer/FuzzedDataProvider.h>

#include <cassert>
#include <cstdio>
#include <limits>
#include <string>
#include <type_traits>

#include "ada.cpp"
#include "ada.h"

// Enforce a tight limit and verify that no operation can produce
// a URL whose serialized form exceeds it.
static constexpr uint32_t kMaxLength = 512;

template <class T>
static void check_length(const T& url, const char* context) {
  if (url.get_href_size() > kMaxLength) {
    printf("FAIL [%s]: href_size=%zu exceeds limit %u\n  href: ", context,
           url.get_href_size(), kMaxLength);
    if constexpr (std::is_same_v<T, ada::url_aggregator>) {
      printf("%.*s\n", (int)url.get_href().size(), url.get_href().data());
    } else {
      printf("%s\n", url.get_href().c_str());
    }
    abort();
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ada::set_max_input_length(kMaxLength);

  FuzzedDataProvider fdp(data, size);

  // Consume strings for initial parse and setter values.
  std::string source = fdp.ConsumeRandomLengthString(1024);
  std::string base_str = fdp.ConsumeRandomLengthString(256);

  // --- Test 1: parse must not produce an href > kMaxLength ---
  auto url = ada::parse<ada::url>(source);
  auto agg = ada::parse<ada::url_aggregator>(source);

  if (url) {
    check_length(*url, "parse<url>");
  }
  if (agg) {
    check_length(*agg, "parse<url_aggregator>");
  }

  // --- Test 2: parse with base ---
  auto base_url = ada::parse<ada::url>(base_str);
  auto base_agg = ada::parse<ada::url_aggregator>(base_str);

  if (base_url) {
    auto result = ada::parse<ada::url>(source, &*base_url);
    if (result) {
      check_length(*result, "parse<url>(source, base)");
    }
  }
  if (base_agg) {
    auto result = ada::parse<ada::url_aggregator>(source, &*base_agg);
    if (result) {
      check_length(*result, "parse<url_aggregator>(source, base)");
    }
  }

  // --- Test 3: setters on a known-good URL ---
  // Start from a short URL to maximise room for setter expansion.
  auto setter_url = ada::parse<ada::url>("http://x/");
  auto setter_agg = ada::parse<ada::url_aggregator>("http://x/");
  if (!setter_url || !setter_agg) return 0;

  // Apply a fuzz-driven sequence of setter calls.
  int steps = fdp.ConsumeIntegralInRange(1, 16);
  for (int i = 0; i < steps && fdp.remaining_bytes() > 0; ++i) {
    std::string val = fdp.ConsumeRandomLengthString(512);
    int which = fdp.ConsumeIntegralInRange(0, 9);
    switch (which) {
      case 0:
        setter_url->set_protocol(val);
        setter_agg->set_protocol(val);
        break;
      case 1:
        setter_url->set_username(val);
        setter_agg->set_username(val);
        break;
      case 2:
        setter_url->set_password(val);
        setter_agg->set_password(val);
        break;
      case 3:
        setter_url->set_hostname(val);
        setter_agg->set_hostname(val);
        break;
      case 4:
        setter_url->set_host(val);
        setter_agg->set_host(val);
        break;
      case 5:
        setter_url->set_pathname(val);
        setter_agg->set_pathname(val);
        break;
      case 6:
        setter_url->set_search(val);
        setter_agg->set_search(val);
        break;
      case 7:
        setter_url->set_hash(val);
        setter_agg->set_hash(val);
        break;
      case 8:
        setter_url->set_port(val);
        setter_agg->set_port(val);
        break;
      case 9:
        setter_url->set_href(val);
        setter_agg->set_href(val);
        break;
    }
    check_length(*setter_url, "setter url");
    check_length(*setter_agg, "setter url_aggregator");
  }

  // --- Test 4: aggressive percent-encoding expansion ---
  // Characters like spaces, control chars, and braces expand 3x when
  // percent-encoded. Try to overflow the limit via these characters.
  {
    auto pe_url = ada::parse<ada::url>("http://x/");
    auto pe_agg = ada::parse<ada::url_aggregator>("http://x/");
    if (pe_url && pe_agg) {
      std::string expanding = fdp.ConsumeRandomLengthString(512);
      pe_url->set_pathname(expanding);
      pe_agg->set_pathname(expanding);
      check_length(*pe_url, "percent-encode pathname url");
      check_length(*pe_agg, "percent-encode pathname url_aggregator");

      pe_url->set_username(expanding);
      pe_agg->set_username(expanding);
      check_length(*pe_url, "percent-encode username url");
      check_length(*pe_agg, "percent-encode username url_aggregator");

      pe_url->set_search(expanding);
      pe_agg->set_search(expanding);
      check_length(*pe_url, "percent-encode search url");
      check_length(*pe_agg, "percent-encode search url_aggregator");

      pe_url->set_hash(expanding);
      pe_agg->set_hash(expanding);
      check_length(*pe_url, "percent-encode hash url");
      check_length(*pe_agg, "percent-encode hash url_aggregator");
    }
  }

  // Reset to default so other tests/fuzzers are not affected.
  ada::set_max_input_length(std::numeric_limits<uint32_t>::max());
  return 0;
}
