#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <memory>
#include <map>

#include "ada.h"
#include "ada/parser.h"


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

    for (auto element : cases) {
      std::string_view new_value = element["new_value"].get_string();
      std::string_view href = element["href"];
      std::string_view comment{};
      if (!element["comment"].get(comment)) {
        std::cout << "    comment: " << comment << std::endl;
      }
      std::string_view encoding{};
      ada::encoding_type type = ada::encoding_type::UTF8;
      if (!element["encoding"].get(encoding)) {
        std::cout << "    encoding: " << encoding << std::endl;
        if(encoding == "UTF-8") {
          type = ada::encoding_type::UTF8;
        } else if(encoding == "UTF-16LE") {
          type = ada::encoding_type::UTF_16LE;
        } else if(encoding == "UTF-16BE") {
          type = ada::encoding_type::UTF_16BE;
        } else {
          std::cerr << "unrecognized encoding" << std::endl;
        }
      }

      auto base = ada_parse(href);
      TEST_ASSERT(base.is_valid, true, "Base url parsing should have succeeded")

      std::cout << "      " << href << std::endl;

      if (category == "protocol") {
        std::string_view expected = element["expected"]["protocol"];
        ada::set_scheme(base, std::string{new_value}, type);
        TEST_ASSERT(std::string(base.get_scheme()) + ":", expected, "Protocol");
      }
      else if (category == "username") {
        std::string_view expected = element["expected"]["username"];
        ada::set_username(base, std::string{new_value});
        TEST_ASSERT(base.username, expected, "Username");
      }
      else if (category == "password") {
        std::string_view expected = element["expected"]["password"];
        ada::set_password(base, std::string{new_value});
        TEST_ASSERT(base.password, expected, "Password");
      }
      else if (category == "hostname") {
        std::string_view expected;

        // TODO: Handle invalid utf-8 tests too.
        if (!element["expected"]["hostname"].get(expected)) {
          ada::set_host(base, std::string{new_value}, type);
          TEST_ASSERT(base.host.value_or(""), expected, "Hostname");
        }
      }
      else if (category == "port") {
        std::string_view expected = element["expected"]["port"];
        ada::set_port(base, std::string{new_value});
        auto normalized = base.port.has_value() ? std::to_string(*base.port) : "";
        TEST_ASSERT(normalized, expected, "Port");
      }
      else if (category == "pathname") {
        std::string_view expected = element["expected"]["pathname"];
        ada::set_pathname(base, std::string{new_value}, type);
        TEST_ASSERT(base.path, expected, "Path");
      }
      else if (category == "search") {
        std::string_view expected = element["expected"]["search"];
        ada::set_search(base, std::string{new_value});
        auto normalized = !base.query.value_or("").empty() ? "?" + base.query.value() : "";
        TEST_ASSERT(normalized, expected, "Search");
      }
      else if (category == "hash") {
        std::string_view expected = element["expected"]["hash"];
        ada::set_hash(base, std::string{new_value});
        auto normalized = !base.fragment.value_or("").empty() ? "#" + *base.fragment : "";
        TEST_ASSERT(normalized, expected, "Fragment");
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
      std::string_view input = object["input"];
      std::optional<std::string> output;
      ada::unicode::to_ascii(output, input, false, input.find('%'));
      auto expected_output = object["output"];

      if (expected_output.type() == ondemand::json_type::string) {
        std::string_view stringified_output = expected_output.get_string();
        TEST_ASSERT(output.value_or(""), stringified_output, "Should have been equal");
      } else if (expected_output.is_null()) {
        TEST_ASSERT(output.value_or(""), "", "Should have been empty");
      }
    }
  }
  TEST_SUCCEED()
}

bool urltestdata_encoding(const char* source) {

  TEST_START()
  ondemand::parser parser;

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
        TEST_ASSERT(input_url.is_valid, !failure, "Should not have succeeded");
      } else {
        TEST_ASSERT(input_url.is_valid, true, "Should not have failed");


        std::string_view protocol = object["protocol"];
         // WPT tests add ":" suffix to protocol
        protocol.remove_suffix(1);
        TEST_ASSERT(input_url.get_scheme(), protocol, "Protocol");

        std::string_view username = object["username"];
        TEST_ASSERT(input_url.username, username, "Username");

        std::string_view password = object["password"];
        TEST_ASSERT(input_url.password, password, "Password");

        std::string_view host = object["host"];
        TEST_ASSERT(input_url.host.value_or("") + (input_url.port.has_value() ? ":" + std::to_string(input_url.port.value()) : ""), host, "Hostname");

        std::string_view hostname = object["hostname"];
        TEST_ASSERT(input_url.host.value_or(""), hostname, "Hostname");

        std::string_view port = object["port"];
        std::string expected_port = (input_url.port.has_value()) ? std::to_string(input_url.port.value()) : "";
        TEST_ASSERT(expected_port, port, "Port");

        std::string_view pathname{};
        if (!object["pathname"].get_string().get(pathname)) {
          std::cout <<"pathname " << pathname<<std::endl;
          TEST_ASSERT(input_url.path, pathname, "Pathname");
        }

        std::string_view query;
        if (!object["query"].get(query)) {
          TEST_ASSERT(input_url.query.value_or(""), query, "Query");
        }

        std::string_view hash = object["hash"];
        if (!hash.empty()) {
          // Test cases start with "#".
          hash.remove_prefix(1);
        }
        TEST_ASSERT(input_url.fragment.value_or(""), hash, "Hash/Fragment");


        std::string_view href = object["href"];
        std::string computed_href = std::string(input_url.get_scheme())
                   +"://"
                   + input_url.username
                   + (input_url.password.empty() ? "" : ":" + input_url.password)
                   + (input_url.includes_credentials() ? "@" : "")
                   + input_url.host.value_or("")
                   + (input_url.port.has_value() ? ":" + std::to_string(input_url.port.value()) : "")
                   + input_url.path 
                   + (input_url.query.has_value() ? "?" +input_url.query.value() : "")
                   + (input_url.fragment.has_value() ? "#" + input_url.fragment.value() : "");
        TEST_ASSERT(computed_href, href, "href");

        std::string_view origin = object["origin"];
        std::string computed_origin = input_url.is_special() ?
                   std::string(input_url.get_scheme())+"://"
                   +input_url.host.value_or("")+(input_url.port.has_value() ? ":" 
                   + std::to_string(input_url.port.value()) : "")
                   : "null";
        TEST_ASSERT(computed_origin, origin, "Origin");
      }
    }
  }
  TEST_SUCCEED()
}

bool verifydnslength_tests(const char* source) {
  TEST_START()
  ondemand::parser parser;

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
      std::string_view input = object["input"].get_string().value();
      std::string_view message = object["message"].get_string().value();
      bool failure = object["failure"].get_bool().value();
      
      ada::url input_url = ada_parse(input);

      TEST_ASSERT(!input_url.is_valid, failure, message);
    }
  }
  TEST_SUCCEED()
}


int main(int argc, char** argv) {
  bool all_tests{true};
  std::string filter;
  if(argc > 1) {
    all_tests = false;
    filter = argv[1];
    std::cout << "Only running tests containing the substring '"<< filter <<"'\n" << std::endl;
  } else {
    std::cout << "You may pass a parameter to the wpt_tests executable to filter the tests, by substring matching." << std::endl;
  }
  std::cout << "Running WPT tests.\n" << std::endl;

  std::map<std::string, bool> results;
  std::string name;
  name = "percent_encoding";
  if(all_tests || name.find(filter) != std::string::npos) {
    results[name] = percent_encoding();
  }
  name = "toascii_encoding";
  if(all_tests || name.find(filter) != std::string::npos) {
    results[name] = toascii_encoding();
  }
  name = "setters_tests_encoding("+std::string(SETTERS_TESTS_JSON)+")";
  if(all_tests || name.find(filter) != std::string::npos) {
    results[name] = setters_tests_encoding(SETTERS_TESTS_JSON);
  }
  name = "setters_tests_encoding("+std::string(ADA_SETTERS_TESTS_JSON)+")";
  if(all_tests || name.find(filter) != std::string::npos) {
    results[name] = setters_tests_encoding(ADA_SETTERS_TESTS_JSON);
  }
  name = "urltestdata_encoding("+std::string(URLTESTDATA_JSON)+")";
  if(all_tests || name.find(filter) != std::string::npos) {
    results[name] = urltestdata_encoding(URLTESTDATA_JSON);
  }
  name = "urltestdata_encoding("+std::string(ADA_URLTESTDATA_JSON)+")";
  if(all_tests || name.find(filter) != std::string::npos) {
    results[name] = urltestdata_encoding(ADA_URLTESTDATA_JSON);
  }
  name = "verifydnslength_tests("+std::string(VERIFYDNSLENGTH_TESTS_JSON)+")";
  if(all_tests || name.find(filter) != std::string::npos) {
    results[name] = verifydnslength_tests(VERIFYDNSLENGTH_TESTS_JSON);
  }
  std::cout << std::endl;
  std::cout << "==============="<< std::endl;
  std::cout << "Final report: "<< std::endl;
  std::cout << "==============="<< std::endl;

  bool one_failed = false;
  for(auto [s,b] : results) {
    std::cout << std::left << std::setw(60) << std::setfill('.') << s << ": " << (b?"SUCCEEDED":"FAILED") << std::endl;
    if(!b) { one_failed = true; }
  }
  if(!one_failed) {
    std::cout << "WPT tests are ok." << std::endl;
    return EXIT_SUCCESS;
  } else {
    return EXIT_FAILURE;
  }
}
