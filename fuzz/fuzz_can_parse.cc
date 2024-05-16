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
   * ada::can_parse
   */
  auto base_source_view =
      std::string_view(base_source.data(), base_source.length());
  ada::can_parse(source);
  ada::can_parse(source, &base_source_view);

  return 0;
}