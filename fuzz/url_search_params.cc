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
   * ada::url_search_params
   */

auto base_source_view =
    std::string_view(base_source.data(), base_source.length());
  auto initialized = ada::url_search_params(base_source_view);

  auto search_params = ada::url_search_params();
  search_params.append(source, base_source);
  search_params.set(source, base_source);
  search_params.to_string();
  if (!search_params.has(base_source)) {
    search_params.append(base_source, source);
  }
  search_params.remove(source);
  search_params.remove(source, base_source);
  if (search_params.has(base_source, source)) {
    search_params.remove(base_source);
    search_params.remove(base_source, source);
  }

  auto keys = search_params.get_keys();
  while (keys.has_next()) {
    keys.next();
  }

  auto values = search_params.get_values();
  while (values.has_next()) {
    values.next();
  }

  auto entries = search_params.get_entries();
  while (entries.has_next()) {
    entries.next();
  }

  return 0;
}