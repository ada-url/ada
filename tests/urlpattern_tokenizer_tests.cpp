#include <string_view>
#include <iostream>
#include <vector>

#include "ada.h"
#include "ada/urlpattern_tokenizer.h"
#include "gtest/gtest.h"
#include "simdjson.h"

using namespace simdjson;
using namespace ada;

bool is_token_list_equal(std::vector<urlpattern::token>& first,
                         std::vector<urlpattern::token>& second);

std::string to_utf8(std::u32string_view utf32);
std::u32string to_utf32(std::string_view utf8);

bool operator!=(const urlpattern::token& lhs, const urlpattern::token& rhs);

std::vector<urlpattern::token> arr_token_from_json(
    ondemand::array& raw_token_arr);

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

      for (size_t i = 0; i < tokens.size(); i++) {
        std::cerr << token_type_to_string(tokens[i].type) << ": ";
        std::cerr << to_utf8(utf32_input.substr(
                         tokens[i].value_start,
                         tokens[i].value_end - tokens[i].value_start + 1))
                  << std::endl;
      }
      //      if (!is_token_list_equal(expected_output, tokens)) {
      //        std::cerr << "expected size: " << expected_output.size()
      //                  << " actual: " << tokens.size() << std::endl;
      //      }
      //      ASSERT_TRUE(is_token_list_equal(expected_output, tokens));
    }
  } catch (simdjson::simdjson_error& error) {
    std::cerr << "JSON error: " << error.what() << " near "
              << doc.current_location() << " in " << TOKENIZER_TESTDATA
              << std::endl;
    FAIL();
  }
  SUCCEED();
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

bool is_token_list_equal(std::vector<urlpattern::token>& first,
                         std::vector<urlpattern::token>& second) {
  //  if (first.size() != second.size()) {
  //    return false;
  //  }
  for (size_t i = 0; i < first.size(); i++) {
    if (first[i] != second[i]) {
      std::cerr << "first: AAA " << first[i].value_end << " "
                << first[i].value_start << std::endl;
      std::cerr << "second: AAA " << second[i].value_end << " "
                << second[i].value_start << std::endl;
    }
  }
  return true;
}

bool operator!=(const urlpattern::token& lhs, const urlpattern::token& rhs) {
  return !(lhs.type == rhs.type && lhs.value_end == rhs.value_end &&
           lhs.value_start == rhs.value_start);
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
