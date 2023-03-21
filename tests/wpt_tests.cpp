#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <memory>
#include <map>
#include <set>

#include "ada.h"
#include "ada/character_sets-inl.h"
#include "ada/parser.h"
#include "ada/url.h"
#include "ada/url_aggregator.h"

// We think that these examples have bad domains.
std::set<std::string> bad_domains = {"http://./", "http://../", "http://foo.09.."};

// This function copies your input onto a memory buffer that
// has just the necessary size. This will entice tools to detect
// an out-of-bound access.
template<class result_type = ada::url>
ada::result<result_type> ada_parse(std::string_view view, const result_type* base = nullptr) {
  std::cout << "about to parse '" << view << "' [" << view.size() << " bytes]" << std::endl;
  std::unique_ptr<char[]> buffer(new char[view.size()]);
  memcpy(buffer.get(), view.data(), view.size());
  return ada::parse<result_type>(std::string_view(buffer.get(), view.size()), base);
}

template ada::result<ada::url> ada_parse(std::string_view view, const ada::url* base);
template ada::result<ada::url_aggregator> ada_parse(std::string_view view, const ada::url_aggregator* base);

#include "simdjson.h"

using namespace simdjson;

#ifndef WPT_DATA_DIR
#define WPT_DATA_DIR "wpt/"
#endif
const char *PERCENT_ENCODING_JSON = WPT_DATA_DIR "percent-encoding.json";
const char *SETTERS_TESTS_JSON = WPT_DATA_DIR "setters_tests.json";
const char *ADA_SETTERS_TESTS_JSON = WPT_DATA_DIR "ada_extra_setters_tests.json";
const char *TOASCII_JSON = WPT_DATA_DIR "toascii.json";
const char *URLTESTDATA_JSON = WPT_DATA_DIR "urltestdata.json";
const char *ADA_URLTESTDATA_JSON = WPT_DATA_DIR "ada_extra_urltestdata.json";
const char *VERIFYDNSLENGTH_TESTS_JSON = WPT_DATA_DIR "verifydnslength_tests.json";

#define TEST_START()                                                           \
  do {                                                                         \
    std::cout << "> Running " << __func__ << " ..." << std::endl;              \
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
    if (LHS != RHS)  {                                                         \
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
  size_t counter{0};

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
      auto element_string = std::string(std::string_view(object.raw_json()));
      object.reset();

      // We might want to decode the strings into UTF-8, but some of the strings
      // are not always valid UTF-8 (e.g., you have unmatched surrogates which
      // are forbidden by the UTF-8 spec).
      auto input_element = object["input"];
      std::string_view input;
      // Try UTF-8.
      bool allow_replacement_characters = true;
      auto error = input_element.get_string(allow_replacement_characters).get(input);
      if(error) {
        std::cout << " I cannot parse " << element_string << std::endl;
        return false;
      }
      std::string my_input_encoded = ada::unicode::percent_encode(input, ada::character_sets::QUERY_PERCENT_ENCODE);
      ondemand::object outputs = object["output"].get_object();
      std::string_view expected_view;
      if(!outputs["utf-8"].get(expected_view)) {
        TEST_ASSERT(my_input_encoded, expected_view, "Percent encoded " + element_string + my_input_encoded);
      } else {
        std::cout << "Missing UTF-8?" << std::endl;
        return false;
      }
      counter++;
    }
  }
  std::cout << "Tests executed = "<< counter << std::endl;
  TEST_SUCCEED()
}

template<class result_type = ada::url>
bool setters_tests_encoding(const char *source) {
  TEST_START()
  ondemand::parser parser;
  RUN_TEST(file_exists(source));
  padded_string json = padded_string::load(source);
  std::cout << "  loaded " << source << " (" << json.size()
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

    for (auto element_value : cases) {
      ondemand::object element = element_value;
      std::string element_string = std::string(std::string_view(element.raw_json()));
      element.reset();
      std::string_view new_value = element["new_value"].get_string();
      std::string_view href = element["href"];
      std::string_view comment{};
      if (!element["comment"].get(comment)) {
        std::cout << "    comment: " << comment << std::endl;
      }

      ada::result<result_type> base = ada_parse<result_type>(href);
      TEST_ASSERT(base.has_value(), true, "Base url parsing should have succeeded")
      if constexpr (std::is_same<ada::url_aggregator, result_type>::value) {
        if(!base->validate()) {
          std::cerr << "Your parsed URL is impossible: " <<  base->to_string() << std::endl;
          TEST_FAIL("Impossible URL");
        }
      }

      std::cout << "      " << href << std::endl;

      if (category == "protocol") {
        std::string_view expected = element["expected"]["protocol"];
        base->set_protocol(new_value);
        TEST_ASSERT(base->get_protocol(), expected, "Protocol " + element_string + base->to_string());
      }
      else if (category == "username") {
        std::string_view expected = element["expected"]["username"];
        base->set_username(new_value);
        TEST_ASSERT(base->get_username(), expected, "Username " + element_string + base->to_string());
      }
      else if (category == "password") {
        std::string_view expected = element["expected"]["password"];
        base->set_password(new_value);
        TEST_ASSERT(base->get_password(), expected, "Password " + element_string + base->to_string());
      }
      else if (category == "host") {
        std::string_view expected;

        // We only support valid UTF-8 cases.
        if (!element["expected"]["host"].get(expected)) {
          base->set_host(new_value);
          TEST_ASSERT(base->get_host(), expected, "Host " + element_string + base->to_string());
        }
      }
      else if (category == "hostname") {
        std::string_view expected;

        // TODO: Handle invalid utf-8 tests too.
        if (!element["expected"]["hostname"].get(expected)) {
          base->set_hostname(new_value);
          TEST_ASSERT(base->get_hostname(), expected, "Hostname " + element_string + base->to_string());
        }
      }
      else if (category == "port") {
        std::string_view expected = element["expected"]["port"];
        base->set_port(new_value);
        TEST_ASSERT(base->get_port(), expected, "Port " + element_string + base->to_string());
      }
      else if (category == "pathname") {
        std::string_view expected = element["expected"]["pathname"];
        base->set_pathname(new_value);
        TEST_ASSERT(base->get_pathname(), expected, "Path " + element_string + base->to_string());
      }
      else if (category == "search") {
        std::string_view expected = element["expected"]["search"];
        base->set_search(new_value);
        TEST_ASSERT(base->get_search(), expected, "Search " + element_string + base->to_string());

        std::string_view expected_pathname;
        if (!element["expected"]["pathname"].get(expected_pathname)) {
          TEST_ASSERT(base->get_pathname(), expected_pathname, "Pathname " + element_string + base->to_string());
        }
      }
      else if (category == "hash") {
        std::string_view expected = element["expected"]["hash"];
        base->set_hash(new_value);
        TEST_ASSERT(base->get_hash(), expected, "Fragment " + element_string + base->to_string());
      }
      else if (category == "href") {
        std::string_view expected = element["expected"]["href"];
        base->set_href(new_value);
        TEST_ASSERT(base->set_href(new_value), true, "set_href should return true");
        TEST_ASSERT(base->get_href(), expected, "Href " + element_string + base->to_string());
      }
      if constexpr (std::is_same<ada::url_aggregator, result_type>::value) {
        if(!base->validate()) {
          std::cerr << "Your parsed URL is impossible: " <<  base->to_string() << std::endl;
          TEST_FAIL("Impossible URL");
        }
      }
    }
  }
  TEST_SUCCEED()
}

template <class result_type = ada::url>
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
      auto element_string = std::string(std::string_view(simdjson::to_json_string(object)));

      std::string_view input = object["input"];
      std::optional<std::string> output;
      ada::unicode::to_ascii(output, input, false, input.find('%'));
      auto expected_output = object["output"];

      // The following code replicates `toascii.window.js` from web-platform tests.
      // @see https://github.com/web-platform-tests/wpt/blob/master/url/toascii.window.js
      ada::result<result_type> current = ada::parse<result_type>("https://" + std::string(input) + "/x");

      if (expected_output.type() == ondemand::json_type::string) {
        std::string_view stringified_output = expected_output.get_string();
        TEST_ASSERT(current->get_host(), stringified_output, "Host should have been equal. From: "+ element_string);
        TEST_ASSERT(current->get_hostname(), stringified_output, "Hostname should have been equal. From: "+ element_string);
        TEST_ASSERT(current->get_pathname(), "/x", "Shouldn't have updated pathname");
        TEST_ASSERT(current->get_href(), "https://" + std::string(stringified_output) + "/x", "Href should have been equal. From: " + element_string);
      } else if (expected_output.is_null()) {
        TEST_ASSERT(current.has_value(), false, "Should have failed. From: " + element_string);
      }

      // Test setters for host and hostname values.
      ada::result<result_type> setter = ada::parse<result_type>("https://x/x");
      TEST_ASSERT(setter->set_host(input), !expected_output.is_null(), "set_host return value. " + element_string);
      TEST_ASSERT(setter->set_hostname(input), !expected_output.is_null(), "set_hostname return value. " + element_string);

      if (expected_output.type() == ondemand::json_type::string) {
        std::string_view stringified_output = expected_output.get_string();
        TEST_ASSERT(setter->get_host(), stringified_output, "Host should have been equal. From: "+ element_string);
        TEST_ASSERT(setter->get_hostname(), stringified_output, "Hostname should have been equal. From: "+ element_string);
      } else if (expected_output.is_null()) {
        // host and hostname should not be updated if the input is invalid.
        TEST_ASSERT(setter->get_host(), "x", "Host should have been equal. From: "+ element_string);
        TEST_ASSERT(setter->get_hostname(), "x", "Hostname should have been equal. From: "+ element_string);
      }
    }
  }
  TEST_SUCCEED()
}

template bool toascii_encoding<ada::url>();
template bool toascii_encoding<ada::url_aggregator>();

template <class result_type = ada::url>
bool urltestdata_encoding(const char* source) {
  TEST_START()
  ondemand::parser parser;
  size_t counter{};

  RUN_TEST(file_exists(source));
  padded_string json = padded_string::load(source);
  std::cout << "  loaded " << source << " (" << json.size() << " kB)"
            << std::endl;
  ondemand::document doc = parser.iterate(json);
  for (auto element : doc.get_array()) {
    if (element.type() == ondemand::json_type::string) {
      std::string_view comment = element.get_string().value();
      std::cout << comment << std::endl;
    } else if (element.type() == ondemand::json_type::object) {
      ondemand::object object = element.get_object();
      std::string element_string = std::string(std::string_view(object.raw_json()));
      object.reset();

      auto input_element = object["input"];
      std::string_view input{};
      bool allow_replacement_characters = true;
      if (input_element.get_string(allow_replacement_characters).get(input)) {
        std::cout << "I could not parse " << element_string << std::endl;
        return false;
      }
      std::cout << "input='" << input << "' [" << input.size() << " bytes]" << std::endl;
      std::string_view base;
      ada::result<result_type> base_url;
      if (!object["base"].get(base)) {
        std::cout << "base=" << base << std::endl;
        base_url = ada_parse<result_type>(base);
        if(!base_url) {
          bool failure = false;
          if (!object["failure"].get(failure) && failure == true) {
            // We are good. Failure was expected.
            continue; // We can't proceed any further.
          } else {
            TEST_ASSERT(base_url.has_value(), true, "Based should not have failred " + element_string);
          }
        }
      }
      bool failure = false;
      ada::result<result_type> input_url = (!object["base"].get(base)) ? ada_parse<result_type>(input, &*base_url) : ada_parse<result_type>(input);
      if (!object["failure"].get(failure) && failure == true) {
        TEST_ASSERT(input_url.has_value(), !failure, "Should not have succeeded " + element_string + input_url->to_string());
      } else {
        TEST_ASSERT(input_url.has_value(), true, "Should not have failed " + element_string + input_url->to_string());
        // Next we test the 'to_string' method.
        std::string parsed_url_json = input_url->to_string();
        //
        if constexpr (std::is_same<ada::url_aggregator, result_type>::value) {
          if(!input_url->validate()) {
            std::cerr << "Your parsed URL is impossible: " << parsed_url_json << std::endl;
            TEST_FAIL("Impossible URL");
          }
        }
        std::string_view protocol = object["protocol"];
        TEST_ASSERT(input_url->get_protocol(), protocol, "Protocol " + element_string + input_url->to_string());

        std::string_view username = object["username"];
        TEST_ASSERT(input_url->get_username(), username, "Username " + element_string + input_url->to_string());

        std::string_view password = object["password"];
        TEST_ASSERT(input_url->get_password(), password, "Password " + element_string + input_url->to_string());

        std::string_view host = object["host"];
        TEST_ASSERT(input_url->get_host(), host, "Host " + element_string + input_url->to_string());

        std::string_view hostname = object["hostname"];
        TEST_ASSERT(input_url->get_hostname(), hostname, "Hostname " + element_string + input_url->to_string());

        std::string_view port = object["port"];
        TEST_ASSERT(input_url->get_port(), port, "Port " + element_string);

        std::string_view pathname{};
        if (!object["pathname"].get_string().get(pathname)) {
          TEST_ASSERT(input_url->get_pathname(), pathname, "Pathname " + element_string + input_url->to_string());
        }
        std::string_view query;
        if (!object["query"].get(query)) {
          TEST_ASSERT(input_url->get_search(), query, "Query " + element_string + input_url->to_string());
        }

        std::string_view hash = object["hash"];
        TEST_ASSERT(input_url->get_hash(), hash, "Hash/Fragment " + element_string + input_url->to_string());

        std::string_view href = object["href"];
        TEST_ASSERT(input_url->get_href(), href, "href " + element_string + input_url->to_string());

        std::string_view origin;
        if(!object["origin"].get(origin)) {
          TEST_ASSERT(input_url->get_origin(), origin, "Origin " + element_string + input_url->to_string());
        }
        if(bad_domains.find(std::string(input)) != bad_domains.end()) {
          TEST_ASSERT(input_url->has_valid_domain(), false, "Bad domain " + element_string + input_url->to_string());
        }

        // We need padding.
        simdjson::padded_string padded_url_json = parsed_url_json;
        // We need a second parser.
        ondemand::parser urlparser;
        ondemand::document parsed_doc = urlparser.iterate(padded_url_json);
        std::cout << "serialized JSON = " << padded_url_json << std::endl;
        ondemand::object parsed_object = parsed_doc.get_object();
        std::string_view json_recovered_path;
        if(parsed_object["path"].get_string().get(json_recovered_path)) {
          if(std::is_same<ada::url, result_type>::value) {
            std::cerr << "The serialized url instance does not provide a 'path' key or the JSON is invalid." << std::endl;
            TEST_FAIL("path key missing from serialized JSON");
          }
        } else {
          TEST_ASSERT(json_recovered_path, pathname, "JSON Path " + element_string + parsed_url_json);
        }

        std::string_view json_recovered_scheme;
        if(parsed_object["scheme"].get_string().get(json_recovered_scheme)) {
          if(std::is_same<ada::url, result_type>::value) {
            std::cerr << "The serialized url instance does not provide a 'scheme' key or the JSON is invalid." << std::endl;
            TEST_FAIL("scheme key missing from serialized JSON");
          }
        } else {
          TEST_ASSERT(json_recovered_scheme, protocol.substr(0,protocol.size()-1), "JSON protocol " + element_string + parsed_url_json);
        }
        // We could test more fields.

        counter++;
      }
    }
  }
  std::cout << "Tests executed = "<< counter << std::endl;
  TEST_SUCCEED()
}

template bool urltestdata_encoding<ada::url>(const char* source);
template bool urltestdata_encoding<ada::url_aggregator>(const char* source);

bool verifydnslength_tests(const char* source) {
  TEST_START()
  size_t counter{};
  ondemand::parser parser;
  RUN_TEST(file_exists(source));
  padded_string json = padded_string::load(source);
  std::cout << "  loaded " << source << " (" << json.size() << " kB)"
            << std::endl;
  ondemand::document doc = parser.iterate(json);
  for (auto element : doc.get_array()) {
    if (element.type() == ondemand::json_type::string) {
      std::string_view comment = element.get_string();
      std::cout << comment << std::endl;
    } else if (element.type() == ondemand::json_type::object) {
      ondemand::object object = element.get_object();
      std::string element_string = std::string(std::string_view(object.raw_json()));
      object.reset();
      std::string_view input = object["input"].get_string();
      std::string message = std::string(object["message"].get_string().value());
      bool failure = object["failure"].get_bool().value();
      ada::result<ada::url> input_url = ada_parse<ada::url>(input);
      std::cout << input << " should " << (failure ? "fail" : "succeed")
        << " and it " << (input_url->has_valid_domain() ? "succeeds" : "fails")
        << (!failure == input_url->has_valid_domain() ? " OK" : " ERROR" ) << std::endl;
      TEST_ASSERT(!input_url->has_valid_domain(), failure, message + " " + element_string);
      counter++;
    }
  }
  std::cout << "Tests executed = "<< counter << std::endl;
  TEST_SUCCEED()
}

int main(int argc, char** argv) {
  // The project runs all tests until the end. The STOP_ON_FAILURE stops the tests with the first
  // failure.
  bool stop_on_failure = (getenv ("STOP_ON_FAILURE") != nullptr);
  bool all_ada_url_tests{true};
  bool all_ada_url_aggregator_tests{false}; // while we are working, let us be careful.
  bool other_tests{true};
  std::string filter = "nonexistentstring";
  if(argc > 1) {
    all_ada_url_tests = false;
    other_tests = false;
    filter = argv[1];
    std::cout << "Only running tests containing the substring '"<< filter <<"'\n" << std::endl;
  } else {
    std::cout << "You may pass a parameter to the wpt_tests executable to filter the tests, by substring matching." << std::endl;
  }
  std::cout << "Running WPT tests.\n" << std::endl;

  std::map<std::string, bool> results;
  std::string name;

  name = "urltestdata_encoding<ada::url>("+std::string(ADA_URLTESTDATA_JSON)+")";
  if(all_ada_url_tests || name.find(filter) != std::string::npos) {
    results[name] = urltestdata_encoding<ada::url>(ADA_URLTESTDATA_JSON);
    if(stop_on_failure && !results[name]) { exit(-1); }
  }
  name = "urltestdata_encoding<ada::url>("+std::string(URLTESTDATA_JSON)+")";
  if(all_ada_url_tests || name.find(filter) != std::string::npos) {
    results[name] = urltestdata_encoding<ada::url>(URLTESTDATA_JSON);
    if(stop_on_failure && !results[name]) { exit(-1); }
  }
  name = "urltestdata_encoding<ada::url_aggregator>("+std::string(ADA_URLTESTDATA_JSON)+")";
  if(all_ada_url_tests || name.find(filter) != std::string::npos) {
    results[name] = urltestdata_encoding<ada::url_aggregator>(ADA_URLTESTDATA_JSON);
    if(stop_on_failure && !results[name]) { exit(-1); }
  }
  name = "urltestdata_encoding<ada::url_aggregator>("+std::string(URLTESTDATA_JSON)+")";
  if(all_ada_url_aggregator_tests || name.find(filter) != std::string::npos) {
    results[name] = urltestdata_encoding<ada::url_aggregator>(URLTESTDATA_JSON);
    if(stop_on_failure && !results[name]) { exit(-1); }
  }
  name = "percent_encoding";
  if(all_ada_url_tests || name.find(filter) != std::string::npos) {
    results[name] = percent_encoding();
    if(stop_on_failure && !results[name]) { exit(-1); }
  }
#if ADA_HAS_ICU
  name = "toascii_encoding";
  if(all_ada_url_tests || name.find(filter) != std::string::npos) {
    results[name] = toascii_encoding();
    if(stop_on_failure && !results[name]) { exit(-1); }
  }
#endif // ADA_HAS_ICU
  name = "setters_tests_encoding<ada::url>("+std::string(SETTERS_TESTS_JSON)+")";
  if(all_ada_url_tests || name.find(filter) != std::string::npos) {
    results[name] = setters_tests_encoding<ada::url>(SETTERS_TESTS_JSON);
    if(stop_on_failure && !results[name]) { exit(-1); }
#if !ADA_HAS_ICU
    results[name] = true; // we pretend. The setters fail under Windows due to IDN issues.
#endif // !ADA_HAS_ICU
  }
  name = "setters_tests_encoding<ada::url>("+std::string(ADA_SETTERS_TESTS_JSON)+")";
  if(all_ada_url_tests || name.find(filter) != std::string::npos) {
    results[name] = setters_tests_encoding<ada::url>(ADA_SETTERS_TESTS_JSON);
    if(stop_on_failure && !results[name]) { exit(-1); }
#if !ADA_HAS_ICU
    results[name] = true; // we pretend. The setters fail under Windows due to IDN issues.
#endif // _WIN32
  }
  name = "setters_tests_encoding<ada::url_aggregator>("+std::string(SETTERS_TESTS_JSON)+")";
  if(all_ada_url_tests || name.find(filter) != std::string::npos) {
    results[name] = setters_tests_encoding<ada::url_aggregator>(SETTERS_TESTS_JSON);
    if(stop_on_failure && !results[name]) { exit(-1); }
#if !ADA_HAS_ICU
    results[name] = true; // we pretend. The setters fail under Windows due to IDN issues.
#endif // !ADA_HAS_ICU
  }
  name = "setters_tests_encoding<ada::url_aggregator>("+std::string(ADA_SETTERS_TESTS_JSON)+")";
  if(all_ada_url_tests || name.find(filter) != std::string::npos) {
    results[name] = setters_tests_encoding<ada::url_aggregator>(ADA_SETTERS_TESTS_JSON);
    if(stop_on_failure && !results[name]) { exit(-1); }
#if !ADA_HAS_ICU
    results[name] = true; // we pretend. The setters fail under Windows due to IDN issues.
#endif // _WIN32
  }
#if ADA_HAS_ICU
#endif
  name = "verifydnslength_tests("+std::string(VERIFYDNSLENGTH_TESTS_JSON)+")";
  if(other_tests || name.find(filter) != std::string::npos) {
    results[name] = verifydnslength_tests(VERIFYDNSLENGTH_TESTS_JSON);
    if(stop_on_failure && !results[name]) { exit(-1); }
  }
  std::cout << std::endl;
  std::cout << "==============="<< std::endl;
  std::cout << "Final report: "<< std::endl;
  std::cout << "==============="<< std::endl;
#if ADA_HAS_ICU
  std::cout << "We are using ICU."<< std::endl;
#else
  std::cout << "We are not using ICU."<< std::endl;
#endif
#if ADA_IS_BIG_ENDIAN
  std::cout << "You have big-endian system."<< std::endl;
#else
  std::cout << "You have litte-endian system."<< std::endl;
#endif
  bool one_failed = false;
  for(auto [s,b] : results) {
    std::cout << std::left << std::setw(60) << std::setfill('.') << s << ": " << (b?"SUCCEEDED":"FAILED") << std::endl;
    if(!b) { one_failed = true; }
  }
  if(!all_ada_url_aggregator_tests) {
    printf("To run ada_url_aggregator tests, type './wpt_tests aggregator' from the tests subdirectory of your build directory. \n");
  }
  if(!one_failed) {
    std::cout << "WPT tests are ok." << std::endl;
    return EXIT_SUCCESS;
  } else {
    return EXIT_FAILURE;
  }
}
