// Credential / hash / pathname setters. Own TU so the unity ada.cpp
// I-cache for parse_url_impl is not shared with the CodSpeed setter
// benches (SetUsername / SetPassword / SetHash). Amalgamation leaves
// ADA_URL_SETTERS_SEPARATE_TU unset and compiles these methods once
// via url_aggregator.cpp.
//
#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

// ada.h pulls parser.h before url.h so ada::parser friends resolve, and
// the *-inl.h bodies that parse_port / is_special need. This TU is not
// part of the amalgamate include tree (ada.cpp never #includes it).
#include "ada.h"
#include "ada/log.h"
#include "ada/unicode-inl.h"

namespace ada {
extern bool max_input_length_customized;
}  // namespace ada

namespace {

// Local copies: unicode/helpers always_inline bodies live in the unity
// TU and have no standalone symbol.
ada_really_inline bool input_has_tab_or_newline(
    std::string_view input) noexcept {
  for (const char c : input) {
    if (c == '\t' || c == '\n' || c == '\r') {
      return true;
    }
  }
  return false;
}

void strip_ascii_tab_or_newline(std::string& input) {
  input.erase(std::remove_if(
                  input.begin(), input.end(),
                  [](char c) { return c == '\t' || c == '\n' || c == '\r'; }),
              input.end());
}

// Same bound as url_aggregator::needs_rollback_snapshot, but without
// jumping into the unity TU (Valgrind I-cache) on every setter call.
ada_really_inline bool setter_needs_rollback(size_t buffer_size,
                                             size_t input_len) noexcept {
  const size_t upper = buffer_size + input_len * 3 + 16;
  if (!ada::max_input_length_customized) [[likely]] {
    return upper > std::numeric_limits<uint32_t>::max();
  }
  return upper > ada::get_max_input_length();
}

}  // namespace

namespace ada {

bool url_aggregator::set_username(const std::string_view input) {
  ada_log("url_aggregator::set_username '", input, "' ");
  ADA_ASSERT_TRUE(validate());
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  std::optional<url_aggregator> saved_url;
  if (setter_needs_rollback(buffer.size(), input.size())) {
    saved_url = *this;
  }
  size_t idx = ada::unicode::percent_encode_index(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  if (idx == input.size()) {
    update_base_username(input);
  } else {
    update_base_username(ada::unicode::percent_encode(
        input, character_sets::USERINFO_PERCENT_ENCODE, idx));
  }
  if (saved_url && buffer.size() > ada::get_max_input_length()) {
    *this = std::move(*saved_url);
    return false;
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

bool url_aggregator::set_password(const std::string_view input) {
  ada_log("url_aggregator::set_password '", input, "'");
  ADA_ASSERT_TRUE(validate());
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  std::optional<url_aggregator> saved_url;
  if (setter_needs_rollback(buffer.size(), input.size())) {
    saved_url = *this;
  }
  size_t idx = ada::unicode::percent_encode_index(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  if (idx == input.size()) {
    update_base_password(input);
  } else {
    update_base_password(ada::unicode::percent_encode(
        input, character_sets::USERINFO_PERCENT_ENCODE, idx));
  }
  if (saved_url && buffer.size() > ada::get_max_input_length()) {
    *this = std::move(*saved_url);
    return false;
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

bool url_aggregator::set_pathname(const std::string_view input) {
  ada_log("url_aggregator::set_pathname ", input);
  ADA_ASSERT_TRUE(validate());
  if (has_opaque_path) {
    return false;
  }
  std::optional<url_aggregator> saved_url;
  if (setter_needs_rollback(buffer.size(), input.size())) {
    saved_url = *this;
  }
  clear_pathname();
  parse_path_outlined(input);
  if (get_pathname().starts_with("//") && !has_authority() && !has_dash_dot()) {
    buffer.insert(components.pathname_start, "/.");
    components.pathname_start += 2;
    if (components.search_start != url_components::omitted) {
      components.search_start += 2;
    }
    if (components.hash_start != url_components::omitted) {
      components.hash_start += 2;
    }
  }
  if (saved_url && buffer.size() > ada::get_max_input_length()) {
    *this = std::move(*saved_url);
    return false;
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

void url_aggregator::set_hash(const std::string_view input) {
  ada_log("url_aggregator::set_hash ", input);
  ADA_ASSERT_TRUE(validate());
  if (input.empty()) {
    if (components.hash_start != url_components::omitted) {
      buffer.resize(components.hash_start);
      components.hash_start = url_components::omitted;
    }
    if (has_opaque_path && !has_search()) {
      std::string path(get_pathname());
      while (!path.empty() && path.back() == ' ') {
        path.resize(path.size() - 1);
      }
      update_base_pathname(path);
    }
    return;
  }

  std::string cleaned;
  std::string_view new_value = input[0] == '#' ? input.substr(1) : input;
  if (input_has_tab_or_newline(new_value)) {
    cleaned.assign(new_value);
    strip_ascii_tab_or_newline(cleaned);
    new_value = cleaned;
  }
  std::optional<url_aggregator> saved_url;
  if (setter_needs_rollback(buffer.size(), new_value.size())) {
    saved_url = *this;
  }
  if (components.hash_start != url_components::omitted) {
    buffer.resize(components.hash_start);
  }
  components.hash_start = uint32_t(buffer.size());
  buffer += '#';
  const size_t idx = ada::unicode::percent_encode_index(
      new_value, ada::character_sets::FRAGMENT_PERCENT_ENCODE);
  if (idx == new_value.size()) {
    buffer.append(new_value);
  } else {
    buffer.append(ada::unicode::percent_encode(
        new_value, ada::character_sets::FRAGMENT_PERCENT_ENCODE, idx));
  }
  if (saved_url && buffer.size() > ada::get_max_input_length()) {
    *this = std::move(*saved_url);
    return;
  }
  ADA_ASSERT_TRUE(validate());
}

}  // namespace ada
