#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(256);
  std::string base_source = fdp.ConsumeRandomLengthString(256);

  /**
   * ada::parse<ada::url>
   */
  auto out_url = ada::parse<ada::url>(source);

  if (out_url) {
    std::string input = fdp.ConsumeRandomLengthString(256);
    out_url->set_protocol(input);
    out_url->set_username(input);
    out_url->set_password(input);
    out_url->set_hostname(input);
    out_url->set_host(input);
    out_url->set_pathname(input);
    out_url->set_search(input);
    out_url->set_hash(input);
    out_url->set_port(input);

    // volatile forces the compiler to store the results without undue
    // optimizations
    volatile size_t length = 0;

    // getters
    length += out_url->get_protocol().size();
    length += out_url->get_username().size();
    length += out_url->get_password().size();
    length += out_url->get_hostname().size();
    length += out_url->get_host().size();
    length += out_url->get_pathname().size();
    length += out_url->get_search().size();
    length += out_url->get_hash().size();
    length += out_url->get_origin().size();
    length += out_url->get_port().size();

    out_url->to_string();
  }

  /**
   * ada::parse<ada::url_aggregator>
   */
  auto out_aggregator = ada::parse<ada::url_aggregator>(source);

  if (out_aggregator) {
    std::string input = fdp.ConsumeRandomLengthString(256);
    out_aggregator->set_protocol(input);
    out_aggregator->set_username(input);
    out_aggregator->set_password(input);
    out_aggregator->set_hostname(input);
    out_aggregator->set_host(input);
    out_aggregator->set_pathname(input);
    out_aggregator->set_search(input);
    out_aggregator->set_hash(input);
    out_aggregator->set_port(input);

    // volatile forces the compiler to store the results without undue
    // optimizations
    volatile size_t length = 0;

    // getters
    length += out_aggregator->get_protocol().size();
    length += out_aggregator->get_username().size();
    length += out_aggregator->get_password().size();
    length += out_aggregator->get_hostname().size();
    length += out_aggregator->get_host().size();
    length += out_aggregator->get_pathname().size();
    length += out_aggregator->get_search().size();
    length += out_aggregator->get_hash().size();
    length += out_aggregator->get_origin().size();
    length += out_aggregator->get_port().size();

    out_aggregator->to_string();
    out_aggregator->to_diagram();

    // clear methods
    out_aggregator->clear_port();
    out_aggregator->clear_search();
    out_aggregator->clear_hash();
  }

  /**
   * Node.js specific
   */
  ada::href_from_file(source);

  return 0;
}  // extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
