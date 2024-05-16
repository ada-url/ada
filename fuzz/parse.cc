#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(256);

  // volatile forces the compiler to store the results without undue
  // optimizations
  volatile size_t length = 0;

  auto parse_url = ada::parse<ada::url>(source);
  auto parse_url_aggregator = ada::parse<ada::url_aggregator>(source);

  if (parse_url) {
    length += parse_url->get_href().size();
  }

  if (parse_url_aggregator) {
    length += parse_url_aggregator->get_href().size();
  }

  /**
   * ada::parse<ada::url>
   */
  auto out_url = ada::parse<ada::url>("https://www.ada-url.com");

  if (out_url) {
    out_url->set_protocol(source);
    out_url->set_username(source);
    out_url->set_password(source);
    out_url->set_hostname(source);
    out_url->set_host(source);
    out_url->set_pathname(source);
    out_url->set_search(source);
    out_url->set_hash(source);
    out_url->set_port(source);

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
  }

  /**
   * ada::parse<ada::url_aggregator>
   */
  auto out_aggregator =
      ada::parse<ada::url_aggregator>("https://www.ada-url.com");

  if (out_aggregator) {
    out_aggregator->set_protocol(source);
    out_aggregator->set_username(source);
    out_aggregator->set_password(source);
    out_aggregator->set_hostname(source);
    out_aggregator->set_host(source);
    out_aggregator->set_pathname(source);
    out_aggregator->set_search(source);
    out_aggregator->set_hash(source);
    out_aggregator->set_port(source);

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
