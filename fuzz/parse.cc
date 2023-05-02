#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString();
  std::string base_source = fdp.ConsumeRandomLengthString();

  /**
   * ada::parse<ada::url>
   */
  auto out_url = ada::parse<ada::url>(source);

  if (out_url) {
    std::string input = fdp.ConsumeRandomLengthString();
    out_url->set_protocol(input);
    out_url->set_username(input);
    out_url->set_password(input);
    out_url->set_hostname(input);
    out_url->set_host(input);
    out_url->set_pathname(input);
    out_url->set_search(input);
    out_url->set_hash(input);
  }

  /**
   * ada::parse<ada::url_aggregator>
   */
  auto out_aggregator = ada::parse<ada::url_aggregator>(source);

  if (out_aggregator) {
    std::string input = fdp.ConsumeRandomLengthString();
    out_aggregator->set_protocol(input);
    out_aggregator->set_username(input);
    out_aggregator->set_password(input);
    out_aggregator->set_hostname(input);
    out_aggregator->set_host(input);
    out_aggregator->set_pathname(input);
    out_aggregator->set_search(input);
    out_aggregator->set_hash(input);
  }

  /**
   * ada::can_parse
   */
  auto base_source_view =
      std::string_view(base_source.data(), base_source.length());
  ada::can_parse(source);
  ada::can_parse(source, &base_source_view);

  return 0;
}  // extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
