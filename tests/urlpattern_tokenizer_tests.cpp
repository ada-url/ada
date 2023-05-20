#include <string_view>
#include <iostream>
#include <vector>

#include "ada.h"
#include "ada/urlpattern_tokenizer.h"
#include "gtest/gtest.h"
#include "simdjson.h"

using namespace simdjson;
using namespace ada;

bool operator!=(const urlpattern::token& lhs, const urlpattern::token& rhs) {
  return !(lhs.type == rhs.type && lhs.value_end == rhs.value_end &&
           lhs.value_start == rhs.value_start);
}

bool is_token_list_equal(std::vector<urlpattern::token>& first,
                         std::vector<urlpattern::token>& second) {
  if (first.size() != second.size()) return false;
  for (size_t i = 0; i < first.size(); i++) {
    if (first[i] != second[i]) {
      return false;
    }
  }
  return true;
}

std::u32string to_utf32(std::string_view utf8) {
  size_t utf32_length =
      ada::idna::utf32_length_from_utf8(utf8.data(), utf8.size());
  std::u32string utf32(utf32_length, '\0');
  idna::utf8_to_utf32(utf8.data(), utf8.size(), utf32.data());

  return utf32;
}

std::vector<urlpattern::token> arr_token_from_json(
    ondemand::array& raw_token_arr) {
  auto token_type_from_string = [](std::string_view type) {
    if (type == "OPEN") return urlpattern::TOKEN_TYPE::OPEN;
    if (type == "CLOSE") return urlpattern::TOKEN_TYPE::CLOSE;
    if (type == "REGEXP") return urlpattern::TOKEN_TYPE::REGEXP;
    if (type == "NAME") return urlpattern::TOKEN_TYPE::NAME;
    if (type == "CHAR") return urlpattern::TOKEN_TYPE::CHAR;
    if (type == "ESCAPED_CHAR") return urlpattern::TOKEN_TYPE::ESCAPED_CHAR;
    if (type == "OTHER_MODIFIER") return urlpattern::TOKEN_TYPE::OTHER_MODIFIER;
    if (type == "ASTERISK") return urlpattern::TOKEN_TYPE::ASTERISK;
    if (type == "END") return urlpattern::TOKEN_TYPE::END;
    if (type == "INVALID_CHAR") return urlpattern::TOKEN_TYPE::INVALID_CHAR;

    unreachable();
  };

  std::vector<urlpattern::token> arr_token{};
  for (auto raw_token : raw_token_arr) {
    auto t = urlpattern::token();
    t.value_start = raw_token["value_start"].get_int64();
    t.value_end = raw_token["value_end"].get_int64();
    t.type = token_type_from_string(raw_token["type"].get_string());
    arr_token.push_back(t);
  }

  return arr_token;
}

std::string_view TOKENIZER_TESTDATA = "urlpattern/tokenizer.json";

TEST(urlpattern_tests, tokenize) {
  ondemand::parser parser;
  padded_string json = padded_string::load(TOKENIZER_TESTDATA);

  ondemand::document doc = parser.iterate(json);
  try {
    for (auto test_case : doc.get_array()) {
      ondemand::object object = test_case.get_object();

      std::string_view utf8_input = object["input"].get_string();
      auto utf32_input = to_utf32(utf8_input);

      ondemand::array raw_expected_output = object["output"].get_array();
      auto expected_output = arr_token_from_json(raw_expected_output);

      auto tokens =
          urlpattern::tokenize(utf32_input, urlpattern::POLICY::LENIENT);

      ASSERT_TRUE(is_token_list_equal(expected_output, tokens));
    }
  } catch (simdjson::simdjson_error& error) {
    std::cerr << "JSON error: " << error.what() << " near "
              << doc.current_location() << " in " << TOKENIZER_TESTDATA
              << std::endl;
    FAIL();
  }
  SUCCEED();
}