#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
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
    for (const auto& v : all_vals) {
      length += v.size();
    }
  }

  // Test sort() on initialized params
  initialized.sort();

  // Test C++ range-for iteration; also verify has(k) and has(k,v) consistency.
  for (const auto& pair : initialized) {
    length += pair.first.size();
    length += pair.second.size();

    // Every key seen in iteration must be reported by has(key).
    if (!initialized.has(pair.first)) {
      printf(
          "url_search_params: iteration yielded key '%s' but has(key) is "
          "false\n",
          std::string(pair.first).c_str());
      abort();
    }

    // has(key, value) → has(key)
    if (initialized.has(pair.first, pair.second) &&
        !initialized.has(pair.first)) {
      printf(
          "url_search_params: has(key,value) is true but has(key) is false "
          "for key '%s'\n",
          std::string(pair.first).c_str());
      abort();
    }

    // get(key) must return a value when the key exists.
    auto got = initialized.get(pair.first);
    if (!got.has_value()) {
      printf(
          "url_search_params: has(key) is true but get(key) returned nullopt "
          "for key '%s'\n",
          std::string(pair.first).c_str());
      abort();
    }
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
    for (const auto& v : all_vals) {
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
  for (const auto& pair : search_params) {
    length += pair.first.size();
    length += pair.second.size();
  }

  // Test reset() - private method used by C API
  std::string resetted_value = fdp.ConsumeRandomLengthString(256);
  search_params.reset(resetted_value);
  length += search_params.size();

  // Test that reset() followed by iteration doesn't crash
  for (const auto& pair : search_params) {
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

  /**
   * Serialisation idempotency.
   *
   * The application/x-www-form-urlencoded serialiser must be a fixed point:
   * parsing the serialised form of any url_search_params and serialising
   * again must produce the same string. This invariant is mandated by the
   * WHATWG spec and must hold for all inputs.
   *
   * We test this on both the initialised params (constructed from fuzz input)
   * and the mutated params (after append / set / remove / sort).
   */

  // Initialised params idempotency.
  {
    std::string s1 = initialized.to_string();
    ada::url_search_params reparsed(s1);
    std::string s2 = reparsed.to_string();
    if (s1 != s2) {
      printf(
          "url_search_params serialisation not idempotent (initialized)!\n"
          "  first:  %s\n  second: %s\n",
          s1.c_str(), s2.c_str());
      abort();
    }
  }

  // Mutated params idempotency.
  {
    std::string s1 = move_assigned.to_string();
    ada::url_search_params reparsed(s1);
    std::string s2 = reparsed.to_string();
    if (s1 != s2) {
      printf(
          "url_search_params serialisation not idempotent (mutated)!\n"
          "  first:  %s\n  second: %s\n",
          s1.c_str(), s2.c_str());
      abort();
    }
  }

  /**
   * Round-trip via URL.
   *
   * Embed the fuzz input as the query component of a real URL, extract the
   * search params from the parsed URL's search string, and verify that the
   * resulting params serialise idempotently. This exercises the interface
   * between URL parsing and search-params parsing.
   */
  {
    std::string url_str = "https://example.com/?" + source;
    auto parsed_url = ada::parse<ada::url_aggregator>(url_str);
    if (parsed_url) {
      std::string search_raw = std::string(parsed_url->get_search());
      std::string_view search_view = search_raw;
      if (!search_view.empty() && search_view[0] == '?') {
        search_view = search_view.substr(1);
      }

      ada::url_search_params sp_from_url(search_view);

      // Size and iteration must not crash.
      length += sp_from_url.size();
      for (const auto& pair : sp_from_url) {
        length += pair.first.size();
        length += pair.second.size();
      }

      // Idempotency check.
      std::string t1 = sp_from_url.to_string();
      ada::url_search_params sp2(t1);
      std::string t2 = sp2.to_string();
      if (t1 != t2) {
        printf(
            "url_search_params via URL round-trip not idempotent!\n"
            "  first:  %s\n  second: %s\n",
            t1.c_str(), t2.c_str());
        abort();
      }

      // Set the serialised params back on the URL – must not crash.
      parsed_url->set_search(t1);
      volatile bool v = parsed_url->validate();
      (void)v;
    }
  }

  return 0;
}
