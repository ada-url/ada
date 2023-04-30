#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <map>
#include <set>

#include "gtest/gtest.h"
#include "ada.h"
#include "ada/character_sets-inl.h"
#include "ada/url_components.h"

// This function copies your input onto a memory buffer that
// has just the necessary size. This will entice tools to detect
// an out-of-bound access.
ada::result<ada::url> ada_parse(std::string_view view,
                                const ada::url* base = nullptr) {
  std::cout << "about to parse '" << view << "' [" << view.size() << " bytes]"
            << std::endl;
  std::unique_ptr<char[]> buffer(new char[view.size()]);
  memcpy(buffer.get(), view.data(), view.size());
  return ada::parse(std::string_view(buffer.get(), view.size()), base);
}

#include "simdjson.h"

using namespace simdjson;

#ifndef WPT_DATA_DIR
#define WPT_DATA_DIR "wpt/"
#endif
const char* URLTESTDATA_JSON = WPT_DATA_DIR "urltestdata.json";

bool file_exists(const char* filename) {
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

void urltestdata_encoding(const char* source) {
  ondemand::parser parser;
  size_t counter{};
  ASSERT_TRUE(file_exists(source));
  padded_string json = padded_string::load(source);
  ondemand::document doc = parser.iterate(json);
  for (auto element : doc.get_array()) {
    if (element.type() == ondemand::json_type::string) {
      std::string_view comment = element.get_string().value();
      std::cout << comment << std::endl;
    } else if (element.type() == ondemand::json_type::object) {
      ondemand::object object = element.get_object();
      std::string element_string =
          std::string(std::string_view(object.raw_json()));
      object.reset();

      auto input_element = object["input"];
      std::string_view input{};
      bool allow_replacement_characters = true;
      ASSERT_FALSE(
          input_element.get_string(allow_replacement_characters).get(input));
      std::cout << "input='" << input << "' [" << input.size() << " bytes]"
                << std::endl;
      std::string_view base;
      ada::result<ada::url> base_url;
      if (!object["base"].get(base)) {
        std::cout << "base=" << base << std::endl;
        base_url = ada_parse(base);
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
      ada::result<ada::url> input_url = (!object["base"].get(base))
                                            ? ada_parse(input, &*base_url)
                                            : ada_parse(input);

      if (object["failure"].get(failure)) {
        auto url = input_url.value();
        auto out = url.get_components();
        auto href = url.get_href();

        ASSERT_EQ(href.substr(0, out.protocol_end), url.get_protocol());

        if (!url.username.empty()) {
          size_t username_start = href.find(url.username);
          ASSERT_EQ(href.substr(username_start, url.username.size()),
                    url.get_username());
        }

        if (!url.password.empty()) {
          size_t password_start = out.username_end + 1;
          ASSERT_EQ(href.substr(password_start, url.password.size()),
                    url.get_password());
        }

        size_t host_start = out.host_start;
        if (url.has_credentials()) {
          ASSERT_EQ(url.get_href()[out.host_start], '@');
          host_start++;
        }
        ASSERT_EQ(href.substr(host_start, url.get_hostname().size()),
                  url.get_hostname());

        if (url.port.has_value()) {
          ASSERT_EQ(out.port, url.port.value());
        } else {
          ASSERT_EQ(out.port, ada::url_components::omitted);
        }

        if (!url.get_pathname().empty()) {
          size_t pathname_end = std::string::npos;
          if (out.search_start != ada::url_components::omitted) {
            pathname_end = out.search_start;
          } else if (out.hash_start != ada::url_components::omitted) {
            pathname_end = out.hash_start;
          }
          ASSERT_EQ(href.substr(out.pathname_start,
                                pathname_end - out.pathname_start),
                    url.get_pathname());
        }

        if (!url.get_search().empty()) {
          ASSERT_EQ(href.substr(out.search_start, url.get_search().size()),
                    url.get_search());
        }

        if (!url.get_hash().empty()) {
          ASSERT_EQ(href.substr(out.hash_start, url.get_hash().size()),
                    url.get_hash());
        }
      }
    }
  }
  std::cout << "Tests executed = " << counter << std::endl;
  SUCCEED();
}

int main(int argc, char** argv) {
  bool all_tests{true};
  std::string filter;
  if (argc > 1) {
    all_tests = false;
    filter = argv[1];
    std::cout << "Only running tests containing the substring '" << filter
              << "'\n"
              << std::endl;
  } else {
    std::cout << "You may pass a parameter to the wpt_tests executable to "
                 "filter the tests, by substring matching."
              << std::endl;
  }
  std::cout << "Running WPT tests.\n" << std::endl;

  std::map<std::string, bool> results;
  std::string name;

  urltestdata_encoding(URLTESTDATA_JSON);
  (void)all_tests;
  std::cout << std::endl;
  std::cout << "===============" << std::endl;
  std::cout << "Final report: " << std::endl;
  std::cout << "===============" << std::endl;
#if ADA_IS_BIG_ENDIAN
  std::cout << "You have big-endian system." << std::endl;
#else
  std::cout << "You have litte-endian system." << std::endl;
#endif
  bool one_failed = false;
  for (auto [s, b] : results) {
    std::cout << std::left << std::setw(60) << std::setfill('.') << s << ": "
              << (b ? "SUCCEEDED" : "FAILED") << std::endl;
    if (!b) {
      one_failed = true;
    }
  }
  if (!one_failed) {
    std::cout << "WPT tests are ok." << std::endl;
    return EXIT_SUCCESS;
  } else {
    return EXIT_FAILURE;
  }
}
