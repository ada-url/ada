#include <algorithm>
#include <ostream>
#include <string>
#include <string_view>
#include <iostream>
#include <vector>
#include <cstring>

#include "ada.h"
#include "ada/urlpattern_tokenizer.h"
#include "gtest/gtest.h"
#include "simdjson.h"

using namespace simdjson;
using namespace ada;

std::string to_utf8(std::u32string_view utf32);
std::u32string to_utf32(std::string_view utf8);

std::string_view TOKENIZER_TESTDATA = "urlpattern/tokenizer.json";

TEST(urlpattern_tests, tokenize) {
  ondemand::parser parser;
  padded_string json = padded_string::load(TOKENIZER_TESTDATA);

  auto token_type_to_string = [](urlpattern::TOKEN_TYPE type) {
    switch (type) {
      case (urlpattern::TOKEN_TYPE::OPEN):
        return "OPEN";
      case (urlpattern::TOKEN_TYPE::CLOSE):
        return "CLOSE";
      case (urlpattern::TOKEN_TYPE::ASTERISK):
        return "ASTERISK";
      case (ada::urlpattern::TOKEN_TYPE::END):
        return "END";
      case (urlpattern::TOKEN_TYPE::REGEXP):
        return "REGEXP";
      case (urlpattern::TOKEN_TYPE::NAME):
        return "NAME";
      case (ada::urlpattern::TOKEN_TYPE::ESCAPED_CHAR):
        return "ESCAPED_CHAR";
      case (urlpattern::TOKEN_TYPE::OTHER_MODIFIER):
        return "OTHER_MODIFIER";
      case (urlpattern::TOKEN_TYPE::INVALID_CHAR):
        return "INVALID_CHAR";
      case (urlpattern::TOKEN_TYPE::CHAR):
        return "CHAR";
    }
  };

  auto token_type_from_string = [](std::string_view type) {
    if (type == "OPEN") return urlpattern::TOKEN_TYPE::OPEN;
    if (type == "CLOSE") return urlpattern::TOKEN_TYPE::CLOSE;
    if (type == "REGEX") return urlpattern::TOKEN_TYPE::REGEXP;
    if (type == "NAME") return urlpattern::TOKEN_TYPE::NAME;
    if (type == "CHAR") return urlpattern::TOKEN_TYPE::CHAR;
    if (type == "ESCAPED_CHAR") return urlpattern::TOKEN_TYPE::ESCAPED_CHAR;
    if (type == "OTHER_MODIFIER") return urlpattern::TOKEN_TYPE::OTHER_MODIFIER;
    if (type == "ASTERISK") return urlpattern::TOKEN_TYPE::ASTERISK;
    if (type == "END") return urlpattern::TOKEN_TYPE::END;
    if (type == "INVALID_CHAR") return urlpattern::TOKEN_TYPE::INVALID_CHAR;

    unreachable();
  };

  ondemand::document doc = parser.iterate(json);
  try {
    for (auto test_case : doc.get_array()) {
      ondemand::object object = test_case.get_object();

      std::string_view utf8_input = object["input"].get_string();
      auto utf32_input = to_utf32(utf8_input);

      ondemand::array raw_expected_output = object["output"].get_array();
      std::vector<urlpattern::token> expected_tokens{};
      std::vector<std::u32string> expected_token_values{};
      for (auto raw_t : raw_expected_output) {
        urlpattern::token expected_t = urlpattern::token();

        expected_t.index = raw_t["index"].get_uint64();
        expected_t.type = token_type_from_string(raw_t["type"].get_string());

        std::string_view u8_value = raw_t["value"].get_string();
        std::u32string u32_value = to_utf32(u8_value);

        // TODO: this is terrible..
        expected_token_values.push_back(u32_value);

        expected_tokens.push_back(expected_t);
      }

      auto tokens =
          urlpattern::tokenize(utf32_input, urlpattern::POLICY::LENIENT);

      if (expected_tokens.size() != tokens.size()) {
        for (auto t : expected_tokens) {
          std::cerr << token_type_to_string(t.type) << std::endl;
        }
        FAIL();
      }

      for (size_t i = 0; i < tokens.size(); i++) {
        ASSERT_TRUE(tokens[i].index == expected_tokens[i].index);
        ASSERT_TRUE(tokens[i].type == expected_tokens[i].type);
        ASSERT_TRUE(tokens[i].value.compare(expected_token_values[i]) == 0);
      }
    }
  } catch (simdjson::simdjson_error& error) {
    std::cerr << "JSON error: " << error.what() << " near "
              << doc.current_location() << " in " << TOKENIZER_TESTDATA
              << std::endl;
    FAIL();
  }
  SUCCEED();
}

std::u32string to_utf32(std::string_view utf8) {
  size_t utf32_length =
      ada::idna::utf32_length_from_utf8(utf8.data(), utf8.size());
  std::u32string utf32(utf32_length, '\0');
  idna::utf8_to_utf32(utf8.data(), utf8.size(), utf32.data());

  return utf32;
}

std::string to_utf8(std::u32string_view utf32) {
  auto utf8_size =
      ada::idna::utf8_length_from_utf32(utf32.data(), utf32.size());
  std::string utf8(utf8_size, '\0');
  ada::idna::utf32_to_utf8(utf32.data(), utf32.size(), utf8.data());

  return utf8;
}
