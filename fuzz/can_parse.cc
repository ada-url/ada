#include <fuzzer/FuzzedDataProvider.h>

#include <cstdio>
#include <string>
#include <string_view>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(256);
  std::string base_source = fdp.ConsumeRandomLengthString(256);

  bool can_parse_result = ada::can_parse(source);
  auto parsed_agg = ada::parse<ada::url_aggregator>(source);
  auto parsed_url = ada::parse<ada::url>(source);

  if (can_parse_result != parsed_agg.has_value()) {
    printf("can_parse vs parse<url_aggregator> inconsistency for: %s\n",
           source.c_str());
    abort();
  }
  if (can_parse_result != parsed_url.has_value()) {
    printf("can_parse vs parse<url> inconsistency for: %s\n", source.c_str());
    abort();
  }
  if (parsed_url.has_value() != parsed_agg.has_value()) {
    printf("parse<url> vs parse<url_aggregator> disagreement for: %s\n",
           source.c_str());
    abort();
  }
  if (parsed_url && parsed_agg &&
      parsed_url->get_href() != std::string(parsed_agg->get_href())) {
    printf("parse href disagreement for: %s\n", source.c_str());
    abort();
  }

  auto base_source_view =
      std::string_view(base_source.data(), base_source.length());
  bool can_parse_with_base = ada::can_parse(source, &base_source_view);

  auto base_agg = ada::parse<ada::url_aggregator>(base_source);
  auto base_url = ada::parse<ada::url>(base_source);
  if (base_agg.has_value() != base_url.has_value()) {
    printf("base parse type disagreement for: %s\n", base_source.c_str());
    abort();
  }

  if (base_agg && base_url) {
    auto ra = ada::parse<ada::url_aggregator>(source, &*base_agg);
    auto ru = ada::parse<ada::url>(source, &*base_url);
    if (can_parse_with_base != ra.has_value()) {
      printf(
          "can_parse_with_base vs parse inconsistency for source=%s base=%s\n",
          source.c_str(), base_source.c_str());
      abort();
    }
    if (ra.has_value() != ru.has_value()) {
      printf("relative parse type disagreement source=%s base=%s\n",
             source.c_str(), base_source.c_str());
      abort();
    }
    if (ra && ru && ru->get_href() != std::string(ra->get_href())) {
      printf("relative parse href disagreement source=%s base=%s\n",
             source.c_str(), base_source.c_str());
      abort();
    }
  } else if (can_parse_with_base) {
    printf("can_parse_with_base true with invalid base=%s\n",
           base_source.c_str());
    abort();
  }

  {
    bool empty_cp = ada::can_parse("");
    auto empty_agg = ada::parse<ada::url_aggregator>("");
    auto empty_url = ada::parse<ada::url>("");
    if (empty_cp != empty_agg.has_value() ||
        empty_cp != empty_url.has_value()) {
      printf("Empty string can_parse/parse disagreement\n");
      abort();
    }
  }

  if (parsed_agg) {
    std::string href = std::string(parsed_agg->get_href());
    if (!ada::can_parse(href)) {
      printf("can_parse rejected normalised href: '%s'\n", href.c_str());
      abort();
    }
    auto reparsed = ada::parse<ada::url_aggregator>(href);
    if (!reparsed || std::string(reparsed->get_href()) != href) {
      printf("href re-parse failure for: '%s'\n", href.c_str());
      abort();
    }
    auto reparsed_url = ada::parse<ada::url>(href);
    if (!reparsed_url || reparsed_url->get_href() != href) {
      printf("parse<url> re-parse disagreement on href: '%s'\n", href.c_str());
      abort();
    }
  }

  return 0;
}
