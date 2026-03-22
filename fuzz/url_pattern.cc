#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

using regex_provider = ada::url_pattern_regex::std_regex_provider;

void exercise_result(auto result) {
  (void)result.get_protocol();
  (void)result.get_username();
  (void)result.get_password();
  (void)result.get_hostname();
  (void)result.get_port();
  (void)result.get_pathname();
  (void)result.get_search();
  (void)result.get_hash();
  (void)result.ignore_case();
  (void)result.has_regexp_groups();
}

// Exercise exec() and test() on a parsed url_pattern with an ASCII input.
// We restrict inputs to ASCII to avoid catastrophic regex backtracking.
static void exercise_exec_and_test(ada::url_pattern<regex_provider>& pattern,
                                   const std::string& test_input,
                                   const std::string& test_base) {
  // test() with string input
  std::string_view test_view(test_input.data(), test_input.size());
  auto test_result = pattern.test(test_view, nullptr);
  (void)test_result;

  // test() with base URL
  if (!test_base.empty()) {
    std::string_view base_view(test_base.data(), test_base.size());
    auto test_result_with_base = pattern.test(test_view, &base_view);
    (void)test_result_with_base;
  }

  // exec() with string input - returns match groups
  auto exec_result = pattern.exec(test_view, nullptr);
  if (exec_result && exec_result->has_value()) {
    const ada::url_pattern_result& match = **exec_result;
    volatile size_t len = 0;
    len += match.protocol.input.size();
    len += match.username.input.size();
    len += match.password.input.size();
    len += match.hostname.input.size();
    len += match.port.input.size();
    len += match.pathname.input.size();
    len += match.search.input.size();
    len += match.hash.input.size();
    (void)len;
  }

  // exec() with base URL
  if (!test_base.empty()) {
    std::string_view base_view(test_base.data(), test_base.size());
    auto exec_with_base = pattern.exec(test_view, &base_view);
    (void)exec_with_base;
  }

  // test() with url_pattern_init input
  ada::url_pattern_init init_input{};
  init_input.pathname = test_input;
  auto test_with_init = pattern.test(init_input, nullptr);
  (void)test_with_init;

  // match() - internal method that exec() uses
  auto match_result = pattern.match(test_view, nullptr);
  (void)match_result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  auto to_ascii = [](const std::string& source) -> std::string {
    std::string result;
    result.reserve(source.size());
    for (char c : source) {
      result.push_back(static_cast<unsigned char>(c) % 128);
    }
    return result;
  };
  FuzzedDataProvider fdp(data, size);
  // We do not want to trigger arbitrary regex matching.
  std::string source_1 = "/" + to_ascii(fdp.ConsumeRandomLengthString(50)) +
                         "/" + to_ascii(fdp.ConsumeRandomLengthString(50));
  std::string base_source_1 = "/" +
                              to_ascii(fdp.ConsumeRandomLengthString(50)) +
                              "/" + to_ascii(fdp.ConsumeRandomLengthString(50));

  std::string source_2 = "https://ada-url.com/*";
  std::string base_source_2 = "https://ada-url.com";

  // Additional test input for exec/test calls (also ASCII-only)
  std::string test_input = "https://" +
                           to_ascii(fdp.ConsumeRandomLengthString(30)) + "/" +
                           to_ascii(fdp.ConsumeRandomLengthString(20));
  std::string test_base = "https://ada-url.com";

  std::array<std::pair<std::string, std::string>, 2> sources = {{
      {source_1, base_source_1},
      {source_2, base_source_2},
  }};

  for (const auto& [source, base_source] : sources) {
    // Without base or options
    auto result =
        ada::parse_url_pattern<regex_provider>(source, nullptr, nullptr);
    if (result) {
      exercise_result(*result);
      exercise_exec_and_test(*result, test_input, test_base);
    }

    // Testing with base_url
    std::string_view base_source_view(base_source.data(), base_source.length());
    auto result_with_base = ada::parse_url_pattern<regex_provider>(
        source, &base_source_view, nullptr);
    if (result_with_base) {
      exercise_result(*result_with_base);
      exercise_exec_and_test(*result_with_base, test_input, test_base);
    }

    // Testing with base_url and options
    ada::url_pattern_options options{.ignore_case = fdp.ConsumeBool()};
    auto result_with_base_and_options = ada::parse_url_pattern<regex_provider>(
        source, &base_source_view, &options);
    if (result_with_base_and_options) {
      exercise_result(*result_with_base_and_options);
      exercise_exec_and_test(*result_with_base_and_options, test_input,
                             test_base);
    }

    // Testing with url_pattern_init and base url.
    int field_index = fdp.ConsumeIntegralInRange(0, 7);
    std::string random_value = to_ascii(fdp.ConsumeRandomLengthString(50));
    ada::url_pattern_init init{};
    switch (field_index) {
      case 0:
        init.protocol = random_value;
        break;
      case 1:
        init.username = random_value;
        break;
      case 2:
        init.password = random_value;
        break;
      case 3:
        init.hostname = random_value;
        break;
      case 4:
        init.port = random_value;
        break;
      case 5:
        init.pathname = random_value;
        break;
      case 6:
        init.search = random_value;
        break;
      case 7:
        init.hash = random_value;
        break;
    }
    auto result_with_init = ada::parse_url_pattern<regex_provider>(
        init, &base_source_view, nullptr);
    if (result_with_init) {
      exercise_result(*result_with_init);
      exercise_exec_and_test(*result_with_init, test_input, test_base);
    }

    // Testing url_pattern_init with ALL fields populated simultaneously
    ada::url_pattern_init init_all{};
    init_all.protocol = to_ascii(fdp.ConsumeRandomLengthString(10));
    init_all.username = to_ascii(fdp.ConsumeRandomLengthString(10));
    init_all.password = to_ascii(fdp.ConsumeRandomLengthString(10));
    init_all.hostname = to_ascii(fdp.ConsumeRandomLengthString(20));
    init_all.port = to_ascii(fdp.ConsumeRandomLengthString(5));
    init_all.pathname = "/" + to_ascii(fdp.ConsumeRandomLengthString(20));
    init_all.search = to_ascii(fdp.ConsumeRandomLengthString(10));
    init_all.hash = to_ascii(fdp.ConsumeRandomLengthString(10));
    auto result_with_init_all =
        ada::parse_url_pattern<regex_provider>(init_all, nullptr, nullptr);
    if (result_with_init_all) {
      exercise_result(*result_with_init_all);
      exercise_exec_and_test(*result_with_init_all, test_input, test_base);
    }
  }

  return 0;
}
