#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(1024);
  std::string base_source = fdp.ConsumeRandomLengthString(1024);

  /**
   * ada::parse<ada::url>
   */
  ada::parse<ada::url>(source);

  /**
   * ada::parse<ada::url_aggregator>
   */
  ada::parse<ada::url_aggregator>(source);

  /**
   * ada::can_parse
   */
  ada::can_parse(source);
  ada::can_parse(source, base_source);

  return 0;
} // extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
