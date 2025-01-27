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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  // We do not want to trigger arbitrary regex matching.
  std::string source =
      "/" + bytesToAlphanumeric(fdp.ConsumeRandomLengthString(50)) + "/" +
      bytesToAlphanumeric(fdp.ConsumeRandomLengthString(50));
  std::string base_source =
      "/" + bytesToAlphanumeric(fdp.ConsumeRandomLengthString(50)) + "/" +
      bytesToAlphanumeric(fdp.ConsumeRandomLengthString(50));

  // Without base or options
  auto result =
      ada::parse_url_pattern<regex_provider>(source, nullptr, nullptr);
  (void)result;

  // Testing with base_url
  std::string_view base_source_view(base_source.data(), base_source.length());
  auto result_with_base = ada::parse_url_pattern<regex_provider>(
      source, &base_source_view, nullptr);
  (void)result_with_base;

  // Testing with base_url and options
  ada::url_pattern_options options{.ignore_case = true};
  auto result_with_base_and_options = ada::parse_url_pattern<regex_provider>(
      source, &base_source_view, &options);
  (void)result_with_base_and_options;

  // Testing with url_pattern_init and base url.
  ada::url_pattern_init init{.protocol = source,
                             .username = source,
                             .password = source,
                             .hostname = source,
                             .port = source,
                             .pathname = source,
                             .search = source,
                             .hash = source};
  auto result_with_init =
      ada::parse_url_pattern<regex_provider>(init, &base_source_view, nullptr);
  (void)result_with_init;

  return 0;
}
