#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(256);
  std::string base_source = fdp.ConsumeRandomLengthString(256);

  // Without base or options
  auto result = ada::parse_url_pattern(source, nullptr, nullptr);
  (void)result;

  // Testing with base_url
  std::string_view base_source_view(base_source.data(), base_source.length());
  auto result_with_base = ada::parse_url_pattern(source, &base_source_view, nullptr);
  (void)result_with_base;

  return 0;
}
