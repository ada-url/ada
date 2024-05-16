#define ADA_DEVELOPMENT_CHECKS 1

#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(256);
  std::string base_source = fdp.ConsumeRandomLengthString(256);

  auto out_url = ada::parse<ada::url>(source);
  if (out_url) {
    volatile size_t length = 0;
    std::string input = fdp.ConsumeRandomLengthString(256);
    out_url->set_href(input);

    length += out_url->get_href().size();
  }

  auto out_aggregator = ada::parse<ada::url_aggregator>(source);
  if (out_aggregator) {
    volatile size_t length = 0;
    std::string input = fdp.ConsumeRandomLengthString(256);
    out_aggregator->set_href(input);

    length += out_aggregator->get_href().size();
  }

  return 0;
}
