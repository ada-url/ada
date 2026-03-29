#include <fuzzer/FuzzedDataProvider.h>

#include <cstdio>
#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(256);
  std::string base_source = fdp.ConsumeRandomLengthString(256);

  /**
   * ada::can_parse consistency checks.
   *
   * can_parse() must agree with parse().has_value() in all cases.
   * This invariant must hold regardless of input encoding.
   */

  // Test 1: can_parse(source) must equal
  // parse<url_aggregator>(source).has_value()
  bool can_parse_result = ada::can_parse(source);
  auto parsed_agg = ada::parse<ada::url_aggregator>(source);
  if (can_parse_result != parsed_agg.has_value()) {
    printf("can_parse vs parse<url_aggregator> inconsistency for: %s\n",
           source.c_str());
    abort();
  }

  // Test 2: can_parse(source) must also equal parse<url>(source).has_value()
  auto parsed_url = ada::parse<ada::url>(source);
  if (can_parse_result != parsed_url.has_value()) {
    printf("can_parse vs parse<url> inconsistency for: %s\n", source.c_str());
    abort();
  }

  // Test 3: can_parse with base
  auto base_source_view =
      std::string_view(base_source.data(), base_source.length());
  bool can_parse_with_base = ada::can_parse(source, &base_source_view);

  // Test 4: can_parse(source, base) must equal parse<url_aggregator>(source,
  // base).has_value()
  auto base_agg = ada::parse<ada::url_aggregator>(base_source);
  if (base_agg) {
    auto parsed_with_base = ada::parse<ada::url_aggregator>(source, &*base_agg);
    if (can_parse_with_base != parsed_with_base.has_value()) {
      printf(
          "can_parse_with_base vs parse<url_aggregator> inconsistency for "
          "source=%s base=%s\n",
          source.c_str(), base_source.c_str());
      abort();
    }
  }

  // Test 5: Empty string edge cases
  {
    std::string_view empty_view;
    bool empty_can_parse = ada::can_parse("");
    auto empty_parsed = ada::parse<ada::url_aggregator>("");
    if (empty_can_parse != empty_parsed.has_value()) {
      printf("Empty string can_parse inconsistency\n");
      abort();
    }
  }

  // Test 6: href round-trip.
  //
  // If parse(source) succeeds, can_parse(href) must return true and
  // re-parsing the href must produce the same href (idempotency).
  // This verifies that the serialised form of every parsed URL is itself
  // a valid absolute URL that round-trips perfectly.
  if (parsed_agg) {
    std::string href = std::string(parsed_agg->get_href());

    // can_parse must accept the normalised href.
    if (!ada::can_parse(href)) {
      printf("can_parse rejected normalised href: '%s'\n", href.c_str());
      abort();
    }

    // Re-parsing the href must succeed.
    auto reparsed = ada::parse<ada::url_aggregator>(href);
    if (!reparsed) {
      printf("Re-parse of href failed: '%s'\n", href.c_str());
      abort();
    }

    // The href of the re-parsed URL must equal the original href.
    std::string href2 = std::string(reparsed->get_href());
    if (href2 != href) {
      printf(
          "href idempotency failure!\n"
          "  href1: %s\n  href2: %s\n",
          href.c_str(), href2.c_str());
      abort();
    }

    // url and url_aggregator must agree on whether the href is parseable.
    bool url_can_parse = ada::parse<ada::url>(href).has_value();
    if (url_can_parse != ada::can_parse(href)) {
      printf("parse<url> vs can_parse disagreement on normalised href: '%s'\n",
             href.c_str());
      abort();
    }
  }

  (void)can_parse_result;
  (void)can_parse_with_base;

  return 0;
}
