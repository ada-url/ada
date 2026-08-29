// Credential and hash setters. Own TU so Valgrind/CodSpeed I-cache for
// SetUsername / SetPassword / SetHash is not charged against the 700 KB
// unity parse object. Rollback is decided with a local helper: calling
// needs_rollback_snapshot() would jump back into ada.cpp.o at ~0x5500
// (that is why the previous isolation recovered only ~0.2 us).
// Amalgamation leaves ADA_URL_SETTERS_SEPARATE_TU unset and compiles
// these methods once via url_aggregator.cpp.
//
#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>

// ada.h pulls parser.h before url.h so ada::parser friends resolve.
// This TU is not part of the amalgamate include tree.
#include "ada.h"
#include "ada/log.h"
#include "ada/unicode-inl.h"

namespace ada {
extern bool max_input_length_customized;
}  // namespace ada

namespace {

// unicode/helpers always_inline bodies live in the unity TU and have no
// standalone symbol. Keep local copies so this object does not take an
// always_inline reference (or a Valgrind jump) back into ada.cpp.o.
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
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  const size_t idx = ada::unicode::percent_encode_index(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  if (setter_needs_rollback(buffer.size(), input.size())) [[unlikely]] {
    url_aggregator saved = *this;
    if (idx == input.size()) {
      update_base_username(input);
    } else {
      update_base_username(ada::unicode::percent_encode(
          input, character_sets::USERINFO_PERCENT_ENCODE, idx));
    }
    if (buffer.size() > ada::get_max_input_length()) {
      *this = std::move(saved);
      return false;
    }
    ADA_ASSERT_TRUE(validate());
    return true;
  }
  if (idx == input.size()) {
    update_base_username(input);
  } else {
    update_base_username(ada::unicode::percent_encode(
        input, character_sets::USERINFO_PERCENT_ENCODE, idx));
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

bool url_aggregator::set_password(const std::string_view input) {
  ada_log("url_aggregator::set_password '", input, "'");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  const size_t idx = ada::unicode::percent_encode_index(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  if (setter_needs_rollback(buffer.size(), input.size())) [[unlikely]] {
    url_aggregator saved = *this;
    if (idx == input.size()) {
      update_base_password(input);
    } else {
      update_base_password(ada::unicode::percent_encode(
          input, character_sets::USERINFO_PERCENT_ENCODE, idx));
    }
    if (buffer.size() > ada::get_max_input_length()) {
      *this = std::move(saved);
      return false;
    }
    ADA_ASSERT_TRUE(validate());
    return true;
  }
  if (idx == input.size()) {
    update_base_password(input);
  } else {
    update_base_password(ada::unicode::percent_encode(
        input, character_sets::USERINFO_PERCENT_ENCODE, idx));
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

void url_aggregator::set_hash(const std::string_view input) {
  ada_log("url_aggregator::set_hash ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
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
  if (setter_needs_rollback(buffer.size(), new_value.size())) [[unlikely]] {
    url_aggregator saved = *this;
    update_unencoded_base_hash(new_value);
    if (buffer.size() > ada::get_max_input_length()) {
      *this = std::move(saved);
      return;
    }
    ADA_ASSERT_TRUE(validate());
    return;
  }
  update_unencoded_base_hash(new_value);
  ADA_ASSERT_TRUE(validate());
}

}  // namespace ada
