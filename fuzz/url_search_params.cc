#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(256);
  std::string base_source = fdp.ConsumeRandomLengthString(256);
  std::string key3 = fdp.ConsumeRandomLengthString(64);
  std::string value3 = fdp.ConsumeRandomLengthString(64);

  /**
   * ada::url_search_params
   */
  volatile size_t length = 0;

  auto base_source_view =
      std::string_view(base_source.data(), base_source.length());

  // Test constructor with initial value
  auto initialized = ada::url_search_params(base_source_view);
  length += initialized.size();
  initialized.to_string();

  // Test get() and get_all() on initialized params
  {
    auto val = initialized.get(source);
    if (val.has_value()) {
      length += val->size();
    }
    auto all_vals = initialized.get_all(source);
    for (const auto &v : all_vals) {
      length += v.size();
    }
  }

  // Test sort() on initialized params
  initialized.sort();

  // Test C++ range-for iteration
  for (const auto &pair : initialized) {
    length += pair.first.size();
    length += pair.second.size();
  }

  // Test index-based access
  if (initialized.size() > 0) {
    auto front = initialized.front();
    length += front.first.size();
    auto back = initialized.back();
    length += back.first.size();
    auto first = initialized[0];
    length += first.first.size();
  }

  // Test default-constructed params with various mutations
  auto search_params = ada::url_search_params();
  search_params.append(source, base_source);
  search_params.append(key3, value3);
  search_params.set(source, base_source);
  search_params.to_string();

  // Test size()
  length += search_params.size();

  // Test has() and has(key, value) overloads
  volatile bool has_key = search_params.has(base_source);
  if (has_key) {
    search_params.append(base_source, source);
  }

  // Test get() - returns first matching value
  {
    auto val = search_params.get(source);
    if (val.has_value()) {
      length += val->size();
    }
  }

  // Test get_all() - returns all matching values
  {
    auto all_vals = search_params.get_all(source);
    length += all_vals.size();
    for (const auto &v : all_vals) {
      length += v.size();
    }
  }

  // Test remove(key) and remove(key, value) overloads
  search_params.remove(source);
  search_params.remove(source, base_source);

  // Test has(key, value) after remove
  if (search_params.has(base_source, source)) {
    search_params.remove(base_source);
    search_params.remove(base_source, source);
  }

  // Append more pairs for iteration testing
  search_params.append(key3, value3);
  search_params.append(source, key3);
  search_params.append(base_source, value3);

  // Test sort()
  search_params.sort();

  // Test serialization after sort
  std::string serialized = search_params.to_string();
  length += serialized.size();

  // Test JavaScript-style iterator: keys
  auto keys = search_params.get_keys();
  while (keys.has_next()) {
    auto k = keys.next();
    if (k.has_value()) {
      length += k->size();
    }
  }

  // Test JavaScript-style iterator: values
  auto values = search_params.get_values();
  while (values.has_next()) {
    auto v = values.next();
    if (v.has_value()) {
      length += v->size();
    }
  }

  // Test JavaScript-style iterator: entries
  auto entries = search_params.get_entries();
  while (entries.has_next()) {
    auto e = entries.next();
    if (e.has_value()) {
      length += e->first.size();
      length += e->second.size();
    }
  }

  // Test C++ range-for on the mutated params
  for (const auto &pair : search_params) {
    length += pair.first.size();
    length += pair.second.size();
  }

  // Test reset() - private method used by C API
  std::string resetted_value = fdp.ConsumeRandomLengthString(256);
  search_params.reset(resetted_value);
  length += search_params.size();

  // Test that reset() followed by iteration doesn't crash
  for (const auto &pair : search_params) {
    length += pair.first.size();
    length += pair.second.size();
  }

  // Test get() after reset
  {
    auto val = search_params.get(source);
    if (val.has_value()) {
      length += val->size();
    }
  }

  // Test copy constructor and copy assignment
  ada::url_search_params copied = search_params;
  length += copied.size();
  ada::url_search_params assigned;
  assigned = search_params;
  length += assigned.size();

  // Test move constructor and move assignment
  ada::url_search_params move_constructed = std::move(copied);
  length += move_constructed.size();
  ada::url_search_params move_assigned;
  move_assigned = std::move(assigned);
  length += move_assigned.size();

  return 0;
}
