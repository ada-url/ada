/**
 * @file url_with_base.cc
 * @brief Fuzz target for relative URL resolution.
 *
 * This target specifically exercises the URL parsing code path where a base
 * URL is provided, covering relative URL resolution (./foo, ../bar, /path,
 * //host/path, etc.) and all the base-URL inheritance logic.
 */
#include <fuzzer/FuzzedDataProvider.h>

#include <cassert>
#include <cstdio>
#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string input = fdp.ConsumeRandomLengthString(256);
  std::string base = fdp.ConsumeRandomLengthString(256);

  volatile size_t length = 0;

  // Parse the base as both url types
  auto base_url = ada::parse<ada::url>(base);
  auto base_agg = ada::parse<ada::url_aggregator>(base);

  /**
   * Test 1: Relative URL parsing with ada::url base
   */
  if (base_url) {
    auto result = ada::parse<ada::url>(input, &*base_url);
    if (result) {
      length += result->get_href().size();
      length += result->get_origin().size();
      length += result->get_protocol().size();
      length += result->get_username().size();
      length += result->get_password().size();
      length += result->get_host().size();
      length += result->get_hostname().size();
      length += result->get_pathname().size();
      length += result->get_search().size();
      length += result->get_hash().size();
      length += result->get_port().size();
      length += result->get_pathname_length();
      (void)result->has_valid_domain();
      (void)result->has_credentials();
      (void)result->has_empty_hostname();
      (void)result->has_hostname();
      (void)result->has_port();
      (void)result->has_hash();
      (void)result->has_search();
      (void)result->get_components();
      length += result->to_string().size();
    }
  }

  /**
   * Test 2: Relative URL parsing with ada::url_aggregator base
   */
  if (base_agg) {
    auto result = ada::parse<ada::url_aggregator>(input, &*base_agg);
    if (result) {
      length += result->get_href().size();
      length += result->get_origin().size();
      length += result->get_protocol().size();
      length += result->get_username().size();
      length += result->get_password().size();
      length += result->get_host().size();
      length += result->get_hostname().size();
      length += result->get_pathname().size();
      length += result->get_search().size();
      length += result->get_hash().size();
      length += result->get_port().size();
      length += result->get_pathname_length();
      (void)result->has_valid_domain();
      (void)result->has_credentials();
      (void)result->has_empty_hostname();
      (void)result->has_hostname();
      (void)result->has_non_empty_username();
      (void)result->has_non_empty_password();
      (void)result->has_password();
      (void)result->has_port();
      (void)result->has_hash();
      (void)result->has_search();
      (void)result->get_components();
      volatile bool v = result->validate();
      (void)v;
      printf("diagram: %s\n", result->to_diagram().c_str());
    }
  }

  /**
   * Test 3: Consistency between url and url_aggregator for relative parsing.
   *
   * When parsing the same (input, base) pair using both URL types, the
   * resulting hrefs must be identical.
   */
  if (base_url && base_agg) {
    auto res_url = ada::parse<ada::url>(input, &*base_url);
    auto res_agg = ada::parse<ada::url_aggregator>(input, &*base_agg);

    if (res_url.has_value() ^ res_agg.has_value()) {
      printf(
          "Relative URL parse inconsistency: input=%s base=%s url=%d agg=%d\n",
          input.c_str(), base.c_str(), res_url.has_value(),
          res_agg.has_value());
      abort();
    }
    if (res_url && res_agg) {
      if (res_url->get_href() != std::string(res_agg->get_href())) {
        printf("Relative URL href mismatch: input=%s base=%s\n", input.c_str(),
               base.c_str());
        abort();
      }
    }
  }

  /**
   * Test 4: can_parse with base must agree with parse
   */
  {
    std::string_view base_view(base.data(), base.size());
    bool can_parse_with_base = ada::can_parse(input, &base_view);

    // Verify consistency with ada::parse using the same base
    if (base_agg) {
      auto res = ada::parse<ada::url_aggregator>(input, &*base_agg);
      if (can_parse_with_base != res.has_value()) {
        printf(
            "can_parse vs parse inconsistency with base: input=%s base=%s\n",
            input.c_str(), base.c_str());
        abort();
      }
    }
  }

  /**
   * Test 5: Chained relative URL resolution.
   *
   * Parse input relative to base, then parse another input relative to the
   * result. This tests multi-level base URL inheritance.
   */
  if (base_agg) {
    auto level1 = ada::parse<ada::url_aggregator>(input, &*base_agg);
    if (level1) {
      // Use the resolved URL as the base for another parse
      std::string input2 = fdp.ConsumeRandomLengthString(128);
      auto level2 = ada::parse<ada::url_aggregator>(input2, &*level1);
      if (level2) {
        length += level2->get_href().size();
        volatile bool v = level2->validate();
        (void)v;
      }
    }
  }

  /**
   * Test 6: Special relative URL patterns with known absolute base.
   *
   * Use a known-good base URL with fuzzed relative inputs to exercise
   * specific relative resolution code paths.
   */
  {
    auto known_base = ada::parse<ada::url_aggregator>("https://example.com/a/b/c?query#hash");
    if (known_base) {
      auto result = ada::parse<ada::url_aggregator>(input, &*known_base);
      if (result) {
        length += result->get_href().size();
        volatile bool v = result->validate();
        (void)v;
      }
    }
  }

  printf("url_with_base length: %zu\n", length);
  return 0;
}
