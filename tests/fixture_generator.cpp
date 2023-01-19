#pragma once

#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string_view>

#include <gtest/gtest.h>

#include "ada.h"
#include "simdjson.h"

using namespace simdjson;

// This function copies your input onto a memory buffer that
// has just the necessary size. This will entice tools to detect
// an out-of-bound access.
ada::url ada_parse(std::string_view view, std::optional<ada::url> base = std::nullopt) {
  std::cout << "about to parse '" << view << "'" << std::endl;
  std::unique_ptr<char[]> buffer(new char[view.size()+1]);
  memcpy(buffer.get(), view.data(), view.size());
  return ada::parse(std::string_view(buffer.get(), view.size()), std::move(base));
}

#include "simdjson.h"

using namespace simdjson;

#ifndef WPT_DATA_DIR
#define WPT_DATA_DIR "wpt/"
#endif
const char *PERCENT_ENCODING_JSON = WPT_DATA_DIR "percent-encoding.json";
const char *SETTERS_TESTS_JSON = WPT_DATA_DIR "setters_tests.json";
const char *TOASCII_JSON = WPT_DATA_DIR "toascii.json";
const char *URLTESTDATA_JSON = WPT_DATA_DIR "urltestdata.json";

bool file_exists(const char *filename) {
  namespace fs = std::filesystem;
  std::filesystem::path f{filename};
  if (std::filesystem::exists(filename)) {
    std::cout << "  file found: " << filename << std::endl;
    return true;
  } else {
    std::cout << "  file missing: " << filename << std::endl;
    return false;
  }
}

struct ToAsciiEncoding {
public:
  std::string_view input;
  std::string_view output;
};

class ToAscii: public testing::TestWithParam<ToAsciiEncoding> {};
std::vector<ToAsciiEncoding> GetTestsForToAsciiEncoding() {
  std::vector<ToAsciiEncoding> out{};

  ondemand::parser parser;
  padded_string json = padded_string::load(TOASCII_JSON);
  ondemand::document doc = parser.iterate(json);
  for (auto element : doc.get_array()) {
    if (element.type() == ondemand::json_type::object) {
      ondemand::object object = element.get_object();
      std::string_view input = object["input"];
      std::optional<std::string> output;

      auto expected_output = object["output"];

      if (expected_output.type() == ondemand::json_type::string) {
        out.push_back(ToAsciiEncoding{input, expected_output.get_string()});
      } else if (expected_output.is_null()) {
        out.push_back(ToAsciiEncoding{input, ""});
      }
    }
  }

  return out;
}
