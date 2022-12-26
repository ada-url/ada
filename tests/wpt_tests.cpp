
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>

#include "ada.h"
#include "simdjson.h"
using namespace simdjson;

#ifndef WPT_DATA_DIR
#define WPT_DATA_DIR "wpt/"
#endif
const char *PERCENT_ENCODING_JSON = WPT_DATA_DIR "percent-encoding.json";
const char *SETTERS_TESTS_JSON = WPT_DATA_DIR "setters_tests.json";
const char *TOASCII_JSON = WPT_DATA_DIR "toascii.json";
const char *URLTESTDATA_JSON = WPT_DATA_DIR "urltestdata.json";

#define TEST_START()                                                           \
  do {                                                                         \
    std::cout << "> Running " << __func__ << " ..." << std::endl;              \
  } while (0);
#define ASSERT_SUCCESS(ACTUAL)                                                 \
  do {                                                                         \
    if (auto err = (ACTUAL); err) {                                            \
      std::cout << err << std::endl;                                           \
      return false;                                                            \
    }                                                                          \
  } while (0);
#define RUN_TEST(ACTUAL)                                                       \
  do {                                                                         \
    if (!(ACTUAL)) {                                                           \
      return false;                                                            \
    }                                                                          \
  } while (0);
#define TEST_FAIL(MESSAGE)                                                     \
  do {                                                                         \
    std::cerr << "FAIL: " << (MESSAGE) << std::endl;                           \
    return false;                                                              \
  } while (0);
#define TEST_SUCCEED()                                                         \
  do {                                                                         \
    return true;                                                               \
  } while (0);
#define TEST_ASSERT(LHS, RHS, MESSAGE)                                         \
  do {                                                                         \
    if (LHS == RHS) { TEST_SUCCEED(); }                                        \
    else {                                                                     \
      std::cerr << "Mismatch: '" << LHS << "' - '" << RHS << "'" << std::endl; \
      TEST_FAIL(MESSAGE);                                                      \
    }                                                                          \
  } while (0);                                                                 \

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

bool percent_encoding() {
  TEST_START()
  ondemand::parser parser;

  RUN_TEST(file_exists(PERCENT_ENCODING_JSON));
  padded_string json = padded_string::load(PERCENT_ENCODING_JSON);
  std::cout << "  loaded " << PERCENT_ENCODING_JSON << " (" << json.size()
            << " kB)" << std::endl;
  ondemand::document doc = parser.iterate(json);
  for (auto element : doc.get_array()) {
    if (element.type() == ondemand::json_type::string) {
      std::cout << "   comment: " << element.get_string() << std::endl;
    } else if (element.type() == ondemand::json_type::object) {
      ondemand::object object = element.get_object();
      // We might want to decode the strings into UTF-8, but some of the strings
      // are not always valid UTF-8 (e.g., you have unmatched surrogates which
      // are forbidden by the UTF-8 spec).
      auto input_element = object["input"];
      std::string_view input;
      auto error = input_element.get_string().get(input);
      if (!error) {
        std::cout << "     input: " << input << std::endl;

      } else {
        // A single surrogate has no accompanying well-defined code point
        // as per the standard.

        input = input_element.raw_json_token(); // points at padded_string json,
        // **unescaped**, has the surrounding quote characters
        std::cout << "    raw input: " << input << std::endl;
        std::cout << "    warning: invalid UTF-8 input!" << std::endl;
      }

      ondemand::object outputs = object["output"].get_object();
      for (auto field : outputs) {
        std::string_view key = field.unescaped_key();
        std::string_view value = field.value().get_string();

        std::cout << "     output[" << key << "]: " << value << std::endl;
      }
    }
  }
  TEST_SUCCEED()
}

bool setters_tests_encoding() {
  TEST_START()
  ondemand::parser parser;
  RUN_TEST(file_exists(SETTERS_TESTS_JSON));
  padded_string json = padded_string::load(SETTERS_TESTS_JSON);
  std::cout << "  loaded " << SETTERS_TESTS_JSON << " (" << json.size()
            << " kB)" << std::endl;
  ondemand::document doc = parser.iterate(json);
  ondemand::object main_object = doc.get_object();
  for (auto mainfield : main_object) {
    std::cout << mainfield.unescaped_key() << std::endl;
    ondemand::array cases = mainfield.value();
    for (auto element : cases) {
      if (element.type() == ondemand::json_type::string) {
        continue;
      }
      std::string_view href = element["href"];
      std::cout << "     href = " << href << std::endl;
      std::string_view newvalue = element["new_value"];
      std::cout << "     new_value = " << newvalue << std::endl;
      ondemand::object expected = element["expected"];
      for (auto field : expected) {
        std::string_view key = field.unescaped_key();
        std::string_view value = field.value().get_string();
        std::cout << "       " << key << " : " << value << std::endl;
      }
    }
  }
  TEST_SUCCEED()
}

bool toascii_encoding() {
  TEST_START()
  ondemand::parser parser;

  RUN_TEST(file_exists(TOASCII_JSON));
  padded_string json = padded_string::load(TOASCII_JSON);
  std::cout << "  loaded " << TOASCII_JSON << " (" << json.size() << " kB)"
            << std::endl;
  ondemand::document doc = parser.iterate(json);
  for (auto element : doc.get_array()) {
    if (element.type() == ondemand::json_type::string) {
      std::cout << "   comment: " << element.get_string() << std::endl;
    } else if (element.type() == ondemand::json_type::object) {
      ondemand::object object = element.get_object();
      std::string_view input =
          object["input"]; // direct access to the JSON document (no escaping)
      std::cout << "     input: " << input << std::endl;

      auto ouput_value = object["output"];
      if (ouput_value.type() == ondemand::json_type::string) {
        std::string_view output = ouput_value.get_string();
        std::cout << "     output: " << output << std::endl;

      } else if (ouput_value.is_null()) {
        std::cout << "     output: null" << std::endl;
      }
    }
  }
  TEST_SUCCEED()
}

bool urltestdata_encoding() {

  TEST_START()
  ondemand::parser parser;

  RUN_TEST(file_exists(URLTESTDATA_JSON));
  padded_string json = padded_string::load(URLTESTDATA_JSON);
  std::cout << "  loaded " << URLTESTDATA_JSON << " (" << json.size() << " kB)"
            << std::endl;
  ondemand::document doc = parser.iterate(json);
  for (auto element : doc.get_array()) {
    if (element.type() == ondemand::json_type::string) {
      std::cout << "     comment: " << element.get_string() << std::endl;
    } else if (element.type() == ondemand::json_type::object) {
      ondemand::object object = element.get_object();
      auto input_element = object["input"];
      std::string_view input;
      auto error = input_element.get_string().get(input);
      if (!error) {
        std::cout << "     input " << input << std::endl;
      } else {
        // we have a non-UTF-8 input.
        input = input_element.raw_json_token();
        std::cout << "     raw input " << input << std::endl;
        // raw input is a quoted string, unescaped.
        std::cout << "    warning: invalid UTF-8 input!" << std::endl;
      }
      std::string_view base;
      std::optional<ada::url> base_url;
      if (!object["base"].get(base)) {
        base_url = ada::parse(base, std::make_optional<ada::url>(), ada::UTF8);
      }
      bool failure = false;
      ada::url input_url = ada::parse(input, base_url, ada::UTF8);
      if (!object["failure"].get(failure)) {
        TEST_ASSERT(input_url.is_valid, !failure, "Failure");
      } else {
        std::string_view href = object["href"];
        std::cout << "     href " << href << std::endl;

        std::string_view origin;
        if (!object["     origin"].get(origin)) {
          // origin is optional.
          std::cout << "     origin " << origin << std::endl;
        }

        std::string_view protocol = object["protocol"];
        // WPT tests add ":" suffix to protocol
        protocol.remove_suffix(1);
        TEST_ASSERT(input_url.scheme, protocol, "Protocol");

        std::string_view username = object["username"];
        std::cout << "     username " << username << std::endl;

        std::string_view password = object["password"];
        std::cout << "     password " << password << std::endl;

        std::string_view host = object["host"];
        std::cout << "     host " << host << std::endl;

        std::string_view hostname = object["hostname"];
        std::cout << "     hostname " << hostname << std::endl;

        std::string_view port = object["port"];
        std::cout << "     port " << port << std::endl;

        std::string_view search = object["search"];
        std::cout << "     search " << search << std::endl;
        std::string_view hash = object["hash"];
        std::cout << "     hash " << hash << std::endl;
      }
    }
  }
  TEST_SUCCEED()
}

int main() {
  std::cout << "Running WPT tests.\n" << std::endl;

  if (percent_encoding() & setters_tests_encoding() & toascii_encoding() &
      urltestdata_encoding()) {
    std::cout << "WPT tests are ok." << std::endl;
    return EXIT_SUCCESS;
  } else {
    return EXIT_FAILURE;
  }
}
