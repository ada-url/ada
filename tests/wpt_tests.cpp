#include <iostream>
#include <string>
#include <memory>
#include <string_view>
#include <gtest/gtest.h>

#include "ada.h"
#include "fixture_generator.cpp"


TEST(WPT, PercentEncoding) {
  ondemand::parser parser;

  ASSERT_TRUE(file_exists(PERCENT_ENCODING_JSON));
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
}

TEST(WPT, SettersTests) {
  ASSERT_TRUE(file_exists(SETTERS_TESTS_JSON));

  ondemand::parser parser;
  padded_string json = padded_string::load(SETTERS_TESTS_JSON);
  std::cout << "  loaded " << SETTERS_TESTS_JSON << " (" << json.size()
            << " kB)" << std::endl;
  ondemand::document doc = parser.iterate(json);
  ondemand::object main_object = doc.get_object();

  for (auto mainfield : main_object) {
    auto category = mainfield.key().value();
    ondemand::array cases = mainfield.value();

    if (category == "comment") {
      continue;
    } else {
       std::cout << "  " << category << ":" << std::endl;
    }

    for (auto element : cases) {
      std::string_view new_value = element["new_value"].get_string();
      std::string_view href = element["href"];
      std::string_view comment{};
      if (!element["comment"].get(comment)) {
        std::cout << "    comment: " << comment << std::endl;
      }

      auto base = ada_parse(href);
      ASSERT_DOUBLE_EQ(base.is_valid, true);

      std::cout << "      " << href << std::endl;

      if (category == "protocol") {
        std::string_view expected = element["expected"]["protocol"];
        ada::set_scheme(base, std::string{new_value});
        ASSERT_EQ(base.get_scheme() + ":", expected);
      }
      else if (category == "username") {
        std::string_view expected = element["expected"]["username"];
        ada::set_username(base, std::string{new_value});
        ASSERT_EQ(base.username, expected);
      }
      else if (category == "password") {
        std::string_view expected = element["expected"]["password"];
        ada::set_password(base, std::string{new_value});
        ASSERT_EQ(base.password, expected);
      }
      else if (category == "hostname") {
        std::string_view expected;

        // TODO: Handle invalid utf-8 tests too.
        if (!element["expected"]["hostname"].get(expected)) {
          ada::set_host(base, std::string{new_value});
          ASSERT_EQ(base.host.value_or(""), expected);
        }
      }
      else if (category == "port") {
        std::string_view expected = element["expected"]["port"];
        ada::set_port(base, std::string{new_value});
        auto normalized = base.port.has_value() ? std::to_string(*base.port) : "";
        ASSERT_EQ(normalized, expected);
      }
      else if (category == "pathname") {
        std::string_view expected = element["expected"]["pathname"];
        ada::set_pathname(base, std::string{new_value});
        ASSERT_EQ(base.path, expected);
      }
      else if (category == "search") {
        std::string_view expected = element["expected"]["search"];
        ada::set_search(base, std::string{new_value});
        auto normalized = !base.query.value_or("").empty() ? "?" + base.query.value() : "";
        ASSERT_EQ(normalized, expected);
      }
      else if (category == "hash") {
        std::string_view expected = element["expected"]["hash"];
        ada::set_hash(base, std::string{new_value});
        auto normalized = !base.fragment.value_or("").empty() ? "#" + *base.fragment : "";
        ASSERT_EQ(normalized, expected);
      }
    }
  }
}

TEST_P(ToAscii, Encoding) {
  std::optional<std::string> input = std::string(GetParam().input);
  ada::parser::to_ascii(input, GetParam().input, false, GetParam().input.find('%'));
  const auto expected = GetParam().output;
  EXPECT_EQ(input.value_or(""), expected);
}

INSTANTIATE_TEST_SUITE_P(WPT, ToAscii, testing::ValuesIn(GetTestsForToAsciiEncoding()));

TEST(WPT, URLTestData) {
  ASSERT_TRUE(file_exists(URLTESTDATA_JSON));

  ondemand::parser parser;
  padded_string json = padded_string::load(URLTESTDATA_JSON);
  std::cout << "  loaded " << URLTESTDATA_JSON << " (" << json.size() << " kB)"
            << std::endl;
  ondemand::document doc = parser.iterate(json);
  for (auto element : doc.get_array()) {
    if (element.type() == ondemand::json_type::string) {
      std::string_view comment = element.get_string().value();
      std::cout << comment << std::endl;
    } else if (element.type() == ondemand::json_type::object) {
      ondemand::object object = element.get_object();
      auto input_element = object["input"];
      std::string_view input{};
      if (input_element.get_string().get(input)) {
        continue;
      }
      std::cout << "input=" << input << std::endl;
      std::string_view base;
      ada::url base_url;
      if (!object["base"].get(base)) {
        std::cout << "base=" << base << std::endl;
        base_url = ada_parse(base);
      }
      bool failure = false;
      ada::url input_url = (!object["base"].get(base)) ?
      ada_parse(input, std::optional<ada::url>(std::move(base_url)))
      : ada_parse(input);

      if (!object["failure"].get(failure)) {
        ASSERT_EQ(input_url.is_valid, !failure);
      } else {
        ASSERT_EQ(input_url.is_valid, true);

        std::string_view protocol = object["protocol"];
         // WPT tests add ":" suffix to protocol
        protocol.remove_suffix(1);
        ASSERT_EQ(input_url.get_scheme(), protocol);

        std::string_view username = object["username"];
        ASSERT_EQ(input_url.username, username);

        std::string_view password = object["password"];
        ASSERT_EQ(input_url.password, password);

        std::string_view hostname = object["hostname"];
        ASSERT_EQ(input_url.host.value_or(""), hostname);

        std::string_view port = object["port"];
        std::string expected_port = (input_url.port.has_value()) ? std::to_string(input_url.port.value()) : "";
        ASSERT_EQ(expected_port, port);

        std::string_view pathname{};
        if (object["pathname"].get_string().get(pathname)) {
          ASSERT_EQ(input_url.path, pathname);
        }

        std::string_view query;
        if (!object["query"].get(query)) {
          ASSERT_EQ(input_url.query.value_or(""), query);
        }

        std::string_view hash = object["hash"];
        if (!hash.empty()) {
          // Test cases start with "#".
          hash.remove_prefix(1);
        }
        ASSERT_EQ(input_url.fragment.value_or(""), hash);
      }
    }
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
