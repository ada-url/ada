#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <sstream>

#include "gtest/gtest.h"
#include "ada.h"
#include "ada/character_sets-inl.h"
#include "ada/parser.h"
#include "ada/url.h"
#include "ada/url_aggregator.h"

// This function copies your input onto a memory buffer that
// has just the necessary size. This will entice tools to detect
// an out-of-bound access.
template <class result_type = ada::url_aggregator>
ada::result<result_type> ada_parse(std::string_view view,
                                   const result_type *base = nullptr) {
  std::cout << "about to parse '" << view << "' [" << view.size() << " bytes]"
            << std::endl;
  std::unique_ptr<char[]> buffer(new char[view.size()]);
  memcpy(buffer.get(), view.data(), view.size());
  return ada::parse<result_type>(std::string_view(buffer.get(), view.size()),
                                 base);
}

template ada::result<ada::url> ada_parse(std::string_view view,
                                         const ada::url *base);
template ada::result<ada::url_aggregator> ada_parse(
    std::string_view view, const ada::url_aggregator *base);

#include "simdjson.h"

using namespace simdjson;

#ifndef WPT_DATA_DIR
#define WPT_DATA_DIR "wpt/"
#endif
const char *PERCENT_ENCODING_JSON = WPT_DATA_DIR "percent-encoding.json";
const char *SETTERS_TESTS_JSON = WPT_DATA_DIR "setters_tests.json";
const char *ADA_SETTERS_TESTS_JSON =
    WPT_DATA_DIR "ada_extra_setters_tests.json";
const char *TOASCII_JSON = WPT_DATA_DIR "toascii.json";
const char *IDNA_TEST_V2 = WPT_DATA_DIR "IdnaTestV2.json";
const char *URLTESTDATA_JSON = WPT_DATA_DIR "urltestdata.json";
const char *ADA_URLTESTDATA_JSON = WPT_DATA_DIR "ada_extra_urltestdata.json";
const char *VERIFYDNSLENGTH_TESTS_JSON =
    WPT_DATA_DIR "verifydnslength_tests.json";

using Types = testing::Types<ada::url, ada::url_aggregator>;
template <class T>
struct wpt_tests_typed : testing::Test {};
TYPED_TEST_SUITE(wpt_tests_typed, Types);

std::stringstream error_buffer;

bool file_exists(const char *filename) {
  namespace fs = std::filesystem;
  std::filesystem::path f{filename};
  if (std::filesystem::exists(filename)) {
    std::cout << "  file found: " << filename << std::endl;
    return true;
  } else {
    std::cerr << "  file missing: " << filename << std::endl;
    error_buffer << "  file missing: " << filename << std::endl;
    return false;
  }
}

TEST(wpt_tests, idna_test_v2_to_ascii) {
  ondemand::parser parser;
  ASSERT_TRUE(file_exists(IDNA_TEST_V2));
  padded_string json = padded_string::load(IDNA_TEST_V2);
  ondemand::document doc = parser.iterate(json);
  try {
    for (auto element : doc.get_array()) {
      if (element.type() == ondemand::json_type::string) {
        continue;
      }

      ondemand::object object = element.get_object();
      auto json_string =
          std::string(std::string_view(simdjson::to_json_string(object)));
      std::string_view input = object["input"].get_string();

      std::optional<std::string> output;
      ada::unicode::to_ascii(output, input, input.find('%'));
      auto expected_output = object["output"];
      auto given_output = output.has_value() ? output.value() : "";

      if (expected_output.is_null()) {
        ASSERT_EQ(given_output, "");
      } else if (expected_output.type() == ondemand::json_type::string) {
        std::string_view str_expected_output = expected_output.get_string();
        ASSERT_EQ(str_expected_output, given_output);
      }
    }
  } catch (simdjson::simdjson_error &error) {
    std::cerr << "JSON error: " << error.what() << " near "
              << doc.current_location() << " in " << TOASCII_JSON << std::endl;
    FAIL();
  }
  SUCCEED();
}

TEST(wpt_tests, percent_encoding) {
  ondemand::parser parser;
  size_t counter{0};

  ASSERT_TRUE(file_exists(PERCENT_ENCODING_JSON));
  padded_string json = padded_string::load(PERCENT_ENCODING_JSON);
  ondemand::document doc = parser.iterate(json);
  try {
    for (auto element : doc.get_array()) {
      if (element.type() == ondemand::json_type::string) {
        std::cout << "   comment: " << element.get_string() << std::endl;
      } else if (element.type() == ondemand::json_type::object) {
        ondemand::object object = element.get_object();
        auto element_string = std::string(std::string_view(object.raw_json()));
        object.reset();

        // We might want to decode the strings into UTF-8, but some of the
        // strings are not always valid UTF-8 (e.g., you have unmatched
        // surrogates which are forbidden by the UTF-8 spec).
        auto input_element = object["input"];
        std::string_view input;
        // Try UTF-8.
        bool allow_replacement_characters = true;
        EXPECT_FALSE(
            input_element.get_string(allow_replacement_characters).get(input));
        std::string my_input_encoded = ada::unicode::percent_encode(
            input, ada::character_sets::QUERY_PERCENT_ENCODE);
        ondemand::object outputs = object["output"].get_object();
        std::string_view expected_view;
        ASSERT_FALSE(outputs["utf-8"].get(expected_view));
        ASSERT_EQ(my_input_encoded, expected_view);
        counter++;
      }
    }
  } catch (simdjson::simdjson_error &error) {
    std::cerr << "JSON error: " << error.what() << " near "
              << doc.current_location() << " in " << TOASCII_JSON << std::endl;
    FAIL();
  }
  std::cout << "Tests executed = " << counter << std::endl;
  SUCCEED();
}

TYPED_TEST(wpt_tests_typed, setters_tests_encoding) {
  for (auto source : {SETTERS_TESTS_JSON, ADA_SETTERS_TESTS_JSON}) {
    ondemand::parser parser;
    ASSERT_TRUE(file_exists(source));
    padded_string json = padded_string::load(source);
    ondemand::document doc = parser.iterate(json);
    try {
      ondemand::object main_object = doc.get_object();

      for (auto mainfield : main_object) {
        auto category = mainfield.key().value();
        ondemand::array cases = mainfield.value();

        if (category == "comment") {
          continue;
        } else {
          std::cout << "  " << category << ":" << std::endl;
        }

        for (auto element_value : cases) {
          ondemand::object element = element_value;
          std::string element_string =
              std::string(std::string_view(element.raw_json()));
          element.reset();
          std::string_view new_value = element["new_value"].get_string();
          std::string_view href = element["href"];
          std::string_view comment{};
          if (!element["comment"].get(comment)) {
            std::cout << "    comment: " << comment << std::endl;
          }

          auto base = ada_parse<TypeParam>(href);
          ASSERT_TRUE(base.has_value());
          if constexpr (std::is_same<ada::url_aggregator, TypeParam>::value) {
            ASSERT_TRUE(base->validate());
            element_string += "\n" + base->to_diagram() + "\n";
          }

          std::cout << "      " << href << std::endl;

          if (category == "protocol") {
            std::string_view expected = element["expected"]["protocol"];
            base->set_protocol(new_value);
            ASSERT_EQ(base->get_protocol(), expected);
          } else if (category == "username") {
            std::string_view expected = element["expected"]["username"];
            base->set_username(new_value);
            ASSERT_EQ(base->get_username(), expected);
          } else if (category == "password") {
            std::string_view expected = element["expected"]["password"];
            base->set_password(new_value);
            ASSERT_EQ(base->get_password(), expected);
          } else if (category == "host") {
            std::string_view expected;

            // We only support valid UTF-8 cases.
            if (!element["expected"]["host"].get(expected)) {
              base->set_host(new_value);
              ASSERT_EQ(base->get_host(), expected);
            }
          } else if (category == "hostname") {
            std::string_view expected;

            // TODO: Handle invalid utf-8 tests too.
            if (!element["expected"]["hostname"].get(expected)) {
              base->set_hostname(new_value);
              ASSERT_EQ(base->get_hostname(), expected);
            }
          } else if (category == "port") {
            std::string_view expected = element["expected"]["port"];
            base->set_port(new_value);
            ASSERT_EQ(base->get_port(), expected);
          } else if (category == "pathname") {
            std::string_view expected = element["expected"]["pathname"];
            base->set_pathname(new_value);
            ASSERT_EQ(base->get_pathname(), expected);
          } else if (category == "search") {
            std::string_view expected = element["expected"]["search"];
            base->set_search(new_value);
            ASSERT_EQ(base->get_search(), expected);

            std::string_view expected_pathname;
            if (!element["expected"]["pathname"].get(expected_pathname)) {
              ASSERT_EQ(base->get_pathname(), expected_pathname);
            }
          } else if (category == "hash") {
            std::string_view expected = element["expected"]["hash"];
            base->set_hash(new_value);
            ASSERT_EQ(base->get_hash(), expected);
          } else if (category == "href") {
            std::string_view expected = element["expected"]["href"];
            base->set_href(new_value);
            ASSERT_TRUE(base->set_href(new_value));
            ASSERT_EQ(base->get_href(), expected);
          }
        }
      }
    } catch (simdjson::simdjson_error &error) {
      std::cerr << "JSON error: " << error.what() << " near "
                << doc.current_location() << " in " << source << std::endl;
      FAIL();
    }
  }
  SUCCEED();
}

TYPED_TEST(wpt_tests_typed, toascii_encoding) {
  ondemand::parser parser;
  ASSERT_TRUE(file_exists(TOASCII_JSON));
  padded_string json = padded_string::load(TOASCII_JSON);
  ondemand::document doc = parser.iterate(json);
  try {
    for (auto element : doc.get_array()) {
      if (element.type() == ondemand::json_type::string) {
        std::cout << "   comment: " << element.get_string() << std::endl;
      } else if (element.type() == ondemand::json_type::object) {
        ondemand::object object = element.get_object();
        auto element_string =
            std::string(std::string_view(simdjson::to_json_string(object)));

        std::string_view input = object["input"];
        std::optional<std::string> output;
        ada::unicode::to_ascii(output, input, input.find('%'));
        auto expected_output = object["output"];

        // The following code replicates `toascii.window.js` from web-platform
        // tests.
        // @see
        // https://github.com/web-platform-tests/wpt/blob/master/url/toascii.window.js
        auto current =
            ada::parse<TypeParam>("https://" + std::string(input) + "/x");

        if (expected_output.type() == ondemand::json_type::string) {
          std::string_view stringified_output = expected_output.get_string();
          ASSERT_EQ(current->get_host(), stringified_output);
          ASSERT_EQ(current->get_hostname(), stringified_output);
          ASSERT_EQ(current->get_pathname(), "/x");
          ASSERT_EQ(current->get_href(),
                    "https://" + std::string(stringified_output) + "/x");
        } else if (expected_output.is_null()) {
          ASSERT_FALSE(current.has_value());
        }

        // Test setters for host and hostname values.
        auto setter = ada::parse<TypeParam>("https://x/x");
        ASSERT_EQ(setter->set_host(input), !expected_output.is_null());
        ASSERT_EQ(setter->set_hostname(input), !expected_output.is_null());

        if (expected_output.type() == ondemand::json_type::string) {
          std::string_view stringified_output = expected_output.get_string();
          ASSERT_EQ(setter->get_host(), stringified_output);
          ASSERT_EQ(setter->get_hostname(), stringified_output);
        } else if (expected_output.is_null()) {
          // host and hostname should not be updated if the input is invalid.
          ASSERT_EQ(setter->get_host(), "x");
          ASSERT_EQ(setter->get_hostname(), "x");
        }
      }
    }
  } catch (simdjson::simdjson_error &error) {
    std::cerr << "JSON error: " << error.what() << " near "
              << doc.current_location() << " in " << TOASCII_JSON << std::endl;
    FAIL();
  }
  SUCCEED();
}

TYPED_TEST(wpt_tests_typed, urltestdata_encoding) {
  for (auto source : {URLTESTDATA_JSON, ADA_URLTESTDATA_JSON}) {
    ondemand::parser parser;
    size_t counter{};
    ASSERT_TRUE(file_exists(source));
    padded_string json = padded_string::load(source);
    ondemand::document doc = parser.iterate(json);
    try {
      for (auto element : doc.get_array()) {
        if (element.type() == ondemand::json_type::string) {
          std::string_view comment = element.get_string().value();
          std::cout << comment << std::endl;
        } else if (element.type() == ondemand::json_type::object) {
          ondemand::object object = element.get_object();
          std::string element_string =
              std::string(std::string_view(object.raw_json()));
          object.reset();

          std::string_view input{};
          bool allow_replacement_characters = true;
          ASSERT_FALSE(object["input"]
                           .get_string(allow_replacement_characters)
                           .get(input));
          std::cout << "input='" << input << "' [" << input.size() << " bytes]"
                    << std::endl;
          std::string_view base;
          ada::result<TypeParam> base_url;
          if (!object["base"].get(base)) {
            std::cout << "base=" << base << std::endl;
            base_url = ada_parse<TypeParam>(base);
            if (!base_url) {
              bool failure = false;
              if (!object["failure"].get(failure) && failure == true) {
                // We are good. Failure was expected.
                continue;  // We can't proceed any further.
              } else {
                ASSERT_TRUE(base_url.has_value());
              }
            }
          }
          bool failure = false;
          auto input_url = (!object["base"].get(base))
                               ? ada_parse<TypeParam>(input, &*base_url)
                               : ada_parse<TypeParam>(input);
          if (!object["failure"].get(failure) && failure == true) {
            ASSERT_EQ(input_url.has_value(), !failure);
          } else {
            ASSERT_TRUE(input_url.has_value());
            // Next we test the 'to_string' method.
            if constexpr (std::is_same<ada::url_aggregator, TypeParam>::value) {
              ASSERT_TRUE(input_url->validate());
            }
            std::string parsed_url_json = input_url->to_string();
            if constexpr (std::is_same<ada::url_aggregator, TypeParam>::value) {
              std::cout << "\n====\n" + input_url->to_diagram() + "\n====\n";
            }
            std::string_view protocol = object["protocol"].get_string();
            ASSERT_EQ(input_url->get_protocol(), protocol);

            std::string_view username = object["username"].get_string();
            ASSERT_EQ(input_url->get_username(), username);

            std::string_view password = object["password"].get_string();
            ASSERT_EQ(input_url->get_password(), password);

            std::string_view host = object["host"].get_string();
            ASSERT_EQ(input_url->get_host(), host);

            std::string_view hostname = object["hostname"].get_string();
            ASSERT_EQ(input_url->get_hostname(), hostname);

            std::string_view port = object["port"].get_string();
            ASSERT_EQ(input_url->get_port(), port);

            std::string_view pathname = object["pathname"].get_string();
            ASSERT_EQ(input_url->get_pathname(), pathname);

            std::string_view search = object["search"].get_string();
            ASSERT_EQ(input_url->get_search(), search);

            std::string_view hash = object["hash"].get_string();
            ASSERT_EQ(input_url->get_hash(), hash);

            std::string_view href = object["href"].get_string();
            ASSERT_EQ(input_url->get_href(), href);

            // The origin key may be missing. In that case, the API's origin
            // attribute is not tested.
            std::string_view origin;
            if (!object["origin"].get(origin)) {
              ASSERT_EQ(input_url->get_origin(), origin);
            }

            // We need padding.
            simdjson::padded_string padded_url_json = parsed_url_json;
            // We need a second parser.
            ondemand::parser urlparser;
            ondemand::document parsed_doc = urlparser.iterate(padded_url_json);
            std::cout << "serialized JSON = " << padded_url_json << std::endl;
            ondemand::object parsed_object = parsed_doc.get_object();
            std::string_view json_recovered_path;
            if (parsed_object["path"].get_string().get(json_recovered_path)) {
              if constexpr (std::is_same<ada::url, TypeParam>::value) {
                std::cerr << "The serialized url instance does not provide a "
                             "'path' key or the JSON is invalid."
                          << std::endl;
                FAIL();
              }
            } else {
              ASSERT_EQ(json_recovered_path, pathname);
            }
            counter++;
          }
        }
      }
    } catch (simdjson::simdjson_error &error) {
      std::cerr << "JSON error: " << error.what() << " near "
                << doc.current_location() << " in " << source << std::endl;
      FAIL();
    }
    std::cout << "Tests executed = " << counter << std::endl;
  }
  SUCCEED();
}

TEST(wpt_tests, verify_dns_length) {
  const char *source = VERIFYDNSLENGTH_TESTS_JSON;
  size_t counter{};
  ondemand::parser parser;
  ASSERT_TRUE(file_exists(source));
  padded_string json = padded_string::load(source);
  ondemand::document doc = parser.iterate(json);
  try {
    for (auto element : doc.get_array()) {
      if (element.type() == ondemand::json_type::string) {
        std::string_view comment = element.get_string();
        std::cout << comment << std::endl;
      } else if (element.type() == ondemand::json_type::object) {
        ondemand::object object = element.get_object();
        std::string element_string =
            std::string(std::string_view(object.raw_json()));
        object.reset();
        std::string_view input = object["input"].get_string();
        std::string message =
            std::string(object["message"].get_string().value());
        bool failure = object["failure"].get_bool().value();
        ada::result<ada::url> input_url = ada_parse<ada::url>(input);
        ASSERT_EQ(!input_url->has_valid_domain(), failure);
        counter++;
      }
    }
  } catch (simdjson::simdjson_error &error) {
    std::cerr << "JSON error: " << error.what() << " near "
              << doc.current_location() << " in " << source << std::endl;
    FAIL();
  }
  std::cout << "Tests executed = " << counter << std::endl;
  SUCCEED();
}
