#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

using regex_provider = ada::url_pattern_regex::std_regex_provider;

std::string bytesToAlphanumeric(const std::string& source) {
  static const char alphanumeric[] =
      "abcdefghijklmnopqrstuvwxyz"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "0123456789";

  std::string result;
  result.reserve(source.size());

  for (char byte : source) {
    int index = static_cast<unsigned char>(byte) % (sizeof(alphanumeric) - 1);
    result.push_back(alphanumeric[index]);
  }

  return result;
}

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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  // We do not want to trigger arbitrary regex matching.
  std::string source_1 =
      "/" + bytesToAlphanumeric(fdp.ConsumeRandomLengthString(50)) + "/" +
      bytesToAlphanumeric(fdp.ConsumeRandomLengthString(50));
  std::string base_source_1 =
      "/" + bytesToAlphanumeric(fdp.ConsumeRandomLengthString(50)) + "/" +
      bytesToAlphanumeric(fdp.ConsumeRandomLengthString(50));

  std::string source_2 = "https://ada-url.com/*";
  std::string base_source_2 = "https://ada-url.com";

  std::array<std::pair<std::string, std::string>, 2> sources = {{
      {source_1, base_source_1},
      {source_2, base_source_2},
  }};

  for (const auto& [source, base_source] : sources) {
    // Without base or options
    auto result =
        ada::parse_url_pattern<regex_provider>(source, nullptr, nullptr);
    if (result) exercise_result(*result);

    // Testing with base_url
    std::string_view base_source_view(base_source.data(), base_source.length());
    auto result_with_base = ada::parse_url_pattern<regex_provider>(
        source, &base_source_view, nullptr);
    if (result_with_base) exercise_result(*result_with_base);

    // Testing with base_url and options
    ada::url_pattern_options options{.ignore_case = fdp.ConsumeBool()};
    auto result_with_base_and_options = ada::parse_url_pattern<regex_provider>(
        source, &base_source_view, &options);
    if (result_with_base_and_options)
      exercise_result(*result_with_base_and_options);

    // Testing with url_pattern_init and base url.
    ada::url_pattern_init init{.protocol = source,
                               .username = source,
                               .password = source,
                               .hostname = source,
                               .port = source,
                               .pathname = source,
                               .search = source,
                               .hash = source};
    auto result_with_init = ada::parse_url_pattern<regex_provider>(
        init, &base_source_view, nullptr);
    if (result_with_init) exercise_result(*result_with_init);
  }

  return 0;
}
