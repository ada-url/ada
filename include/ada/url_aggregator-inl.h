/**
 * @file url_aggregator-inl.h
 * @brief Inline functions for url aggregator
 */
#ifndef ADA_URL_AGGREGATOR_INL_H
#define ADA_URL_AGGREGATOR_INL_H

#include "ada/character_sets.h"
#include "ada/character_sets-inl.h"
#include "ada/helpers.h"
#include "ada/unicode.h"
#include "ada/url_aggregator.h"
#include "ada/url_components.h"
#include "ada/scheme.h"
#include "ada/log.h"

#include <optional>
#include <string_view>

namespace ada {

inline void url_aggregator::update_unencoded_base_hash(std::string_view input) {
  ada_log("url_aggregator::update_unencoded_base_hash ", input, " [", input.size(), " bytes], buffer is '", buffer, "' [", buffer.size(), " bytes] components.hash_start = ", components.hash_start);

  if (components.hash_start != url_components::omitted) {
    buffer.resize(components.hash_start);
  }
  components.hash_start = uint32_t(buffer.size());
  buffer += "#";
  bool encoding_required = unicode::percent_encode<true>(input,ada::character_sets::FRAGMENT_PERCENT_ENCODE, buffer);
  // When encoding_required is false, then buffer is left unchanged, and percent encoding was not deemed required.
  if (!encoding_required) { buffer.append(input); }
  ada_log("url_aggregator::update_unencoded_base_hash final buffer is '", buffer, "' [", buffer.size(), " bytes]");
}

inline void url_aggregator::update_base_hostname(std::string_view input) {
  ada_log("url_aggregator::update_base_hostname ", input, " [", input.size(), " bytes], buffer is '", buffer, "' [", buffer.size()," bytes]");

  add_authority_slashes_if_needed();

  uint32_t input_size = uint32_t(input.size());
  uint32_t current_length = components.host_end - components.host_start;
  uint32_t new_difference = 0;
  // The common case is current_length == 0.
  buffer.erase(components.host_start, current_length);

  if (input.empty()) {
    // This is uncommon!
    buffer.erase(components.host_start, current_length);
    components.host_end = components.host_start;
    components.pathname_start -= current_length;
    if (components.search_start != url_components::omitted) { components.search_start -= current_length; }
    if (components.hash_start != url_components::omitted) { components.hash_start -= current_length; }
  } else {
    new_difference = input_size - current_length;
    // The common case is components.host_start == buffer.size().
    buffer.insert(components.host_start, input);
  }

  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != url_components::omitted) { components.search_start += new_difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += new_difference; }
}

ada_really_inline uint32_t url_aggregator::get_pathname_length() const noexcept {
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) { ending_index = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  return ending_index - components.pathname_start;
}

[[nodiscard]] ada_really_inline bool url_aggregator::is_at_path()  const noexcept {
  return buffer.size() == components.pathname_start;
}

inline void url_aggregator::update_base_search(std::string_view input) {
  ada_log("url_aggregator::update_base_search ", input);

  if (input.empty()) {
    clear_base_search();
    return;
  }

  // Make sure search is deleted and hash_start index is correct.
  if (components.search_start != url_components::omitted) { // Uncommon path
    uint32_t search_end = uint32_t(buffer.size());
    if (components.hash_start != url_components::omitted) {
      search_end = components.hash_start;
      components.hash_start = components.search_start;
    }
    buffer.erase(components.search_start, search_end - components.search_start);
  }

  uint32_t input_size = uint32_t(input.size() + 1); // add `?` prefix
  components.search_start = components.pathname_start + get_pathname_length();
  // The common case here is components.search_start == buffer.size().
  buffer.insert(components.search_start, helpers::concat("?", input));
  if (components.hash_start != url_components::omitted) { components.hash_start += input_size; }
}

inline void url_aggregator::update_base_search(std::string_view input, const uint8_t query_percent_encode_set[]) {
  ada_log("url_aggregator::update_base_search ", input, " with encoding parameter ", to_string());

  // Make sure search is deleted and hash_start index is correct.
  if (components.search_start != url_components::omitted) { // uncommon path
    uint32_t search_end = uint32_t(buffer.size());
    if (components.hash_start != url_components::omitted) {
      search_end = components.hash_start;
      components.hash_start = components.search_start;
    }
    buffer.erase(components.search_start, search_end - components.search_start);
  } else {
    uint32_t search_ends = uint32_t(buffer.size());
    if (components.hash_start != url_components::omitted) { search_ends = components.hash_start; }
    components.search_start = search_ends;
  }
  // The common case is components.search_start == buffer.size().
  buffer.insert(components.search_start, "?");

  if (components.hash_start == url_components::omitted) { // common case
    bool encoding_required = unicode::percent_encode<true>(input, query_percent_encode_set, buffer);
    // When encoding_required is false, then buffer is left unchanged, and percent encoding was not deemed required.
    if (!encoding_required) { buffer.append(input); }
  } else { // slow path
    std::string encoded = unicode::percent_encode(input, query_percent_encode_set);
    buffer.insert(components.search_start + 1, encoded);
    components.hash_start += uint32_t(encoded.size() + 1); // Do not forget `?`
  }
}

inline void url_aggregator::update_base_pathname(const std::string_view input) {
  ada_log("url_aggregator::update_base_pathname ", input, " ", to_string());

  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) { ending_index = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }

  uint32_t current_length = ending_index - components.pathname_start;
  uint32_t difference = uint32_t(input.size()) - current_length;
  // The common case is current_length == 0.
  buffer.erase(components.pathname_start, current_length);
  // The common case is components.pathname_start == buffer.size() so this is effectively an append.
  buffer.insert(components.pathname_start, input);

  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
}

inline void url_aggregator::append_base_pathname(const std::string_view input) {
  ada_log("url_aggregator::append_base_pathname ", input, " ", to_string());
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) { ending_index = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  buffer.insert(ending_index, input);

  uint32_t difference = uint32_t(input.size());
  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
}

inline void url_aggregator::update_base_username(const std::string_view input) {
  ada_log("url_aggregator::update_base_username ", input, " ", to_string());

  add_authority_slashes_if_needed();

  uint32_t input_size = uint32_t(input.size());
  uint32_t username_start = components.protocol_end + 2;
  uint32_t difference = input_size;

  if (username_start == components.username_end) {
    buffer.insert(username_start, input);
  } else {
    buffer.erase(username_start, components.username_end);
    buffer.insert(username_start, input);
    difference -= components.username_end - username_start;
  }

  components.username_end += difference;
  components.host_start += difference;
  components.host_end += difference;
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
}

inline void url_aggregator::append_base_username(const std::string_view input) {
  ada_log("url_aggregator::append_base_username ", input);

  // If input is empty, do nothing.
  if (input.empty()) { return; }

  add_authority_slashes_if_needed();

  uint32_t difference = uint32_t(input.size());
  buffer.insert(components.username_end, input);
  components.username_end += uint32_t(input.size());

  if (buffer[components.username_end] != '@') {
    buffer.insert(components.username_end, "@");
    difference++;
  }

  components.host_start += difference;
  components.host_end += difference;
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
}

inline void url_aggregator::update_base_password(const std::string_view input) {
  ada_log("url_aggregator::update_base_password ", input);
  // TODO: Implement this
  void(input.size());
}

inline void url_aggregator::append_base_password(const std::string_view input) {
  ada_log("url_aggregator::append_base_password ", input, " ", to_string());

  // If input is empty, do nothing.
  if (input.empty()) { return; }

  bool has_password = buffer[components.username_end] == ':';
  uint32_t difference = uint32_t(input.size());

  if (has_password) {
    uint32_t password_end = components.host_start - 2; // For "@"
    buffer.insert(password_end, input);
  } else {
    difference++; // Increment for ":"
    buffer.insert(components.username_end, ":");
    buffer.insert(components.username_end + 1, input);
  }

  components.host_start += difference;
  components.host_end += difference;
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
}

inline void url_aggregator::update_base_port(std::optional<uint16_t> input) {
  ada_log("url_aggregator::update_base_port");

  if (!input.has_value()) {
    clear_base_port();
    return;
  }
  // calling std::to_string(input.value()) is unfortunate given that the port
  // value is probably already available as a string.
  std::string value = helpers::concat(":", std::to_string(input.value()));
  uint32_t difference = uint32_t(value.size());

  if (components.port != url_components::omitted) {
    difference -= components.pathname_start - components.host_end;
    buffer.erase(components.host_end, components.pathname_start - components.host_end);
  }

  buffer.insert(components.host_end, value);
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
  components.port = input.value();
}

inline void url_aggregator::clear_base_port() {
  ada_log("url_aggregator::clear_base_port");

  if (components.port == url_components::omitted) { return; }
  uint32_t length = components.pathname_start - components.host_end;
  buffer.erase(components.host_end, length);
  components.pathname_start -= length;
  if (components.search_start != url_components::omitted) { components.search_start -= length; }
  if (components.hash_start != url_components::omitted) { components.hash_start -= length; }
  components.port = url_components::omitted;
}

inline std::optional<uint16_t> url_aggregator::retrieve_base_port() const {
  ada_log("url_aggregator::retrieve_base_port");
  if (components.port == url_components::omitted) {
    return std::nullopt;
  }
  return components.port;
}

inline std::string_view url_aggregator::retrieve_base_pathname() const {
  ada_log("url_aggregator::retrieve_base_pathname");
  size_t ending = buffer.size();
  if (components.search_start != url_components::omitted) { ending = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending = components.hash_start; }
  return helpers::substring(buffer, components.pathname_start, ending);
}

inline void url_aggregator::clear_base_search() {
  if (components.search_start == url_components::omitted) { return; }

  if (components.hash_start == url_components::omitted) {
    buffer.resize(components.search_start);
  } else {
    buffer.erase(components.search_start, components.hash_start - components.search_start);
    components.hash_start = components.search_start;
  }

  components.search_start = url_components::omitted;
}

inline void url_aggregator::clear_base_pathname() {
  ada_log("url_aggregator::clear_base_pathname");
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) { ending_index = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  uint32_t pathname_length = components.pathname_start - ending_index;
  buffer.erase(components.pathname_start, pathname_length);
  if (components.search_start != url_components::omitted) { components.search_start += pathname_length; }
  if (components.hash_start != url_components::omitted) { components.hash_start += pathname_length; }
}

inline void url_aggregator::clear_base_hostname() {
  ada_log("url_aggregator::clear_base_hostname");
  bool has_double_dash_in_url = components.host_start > components.protocol_end;
  uint32_t length = components.host_start - components.host_end;

  // Remove `//` in the URL when clearing the hostname
  if (has_double_dash_in_url) {
    length -= 2;
    components.host_start -= 2;
  }
  if (length == 0 && !has_double_dash_in_url) { return; }
  buffer.erase(components.host_start, components.host_end - components.host_start);
  components.host_end = components.host_start;
  components.pathname_start += length;
  if (components.search_start != url_components::omitted) { components.search_start += length; }
  if (components.hash_start != url_components::omitted) { components.hash_start += length; }
}

inline bool url_aggregator::base_fragment_has_value() const {
  ada_log("url_aggregator::base_fragment_has_value");
  return components.hash_start != url_components::omitted;
}

inline bool url_aggregator::base_search_has_value() const {
  ada_log("url_aggregator::base_search_has_value");
  return components.search_start != url_components::omitted;
}

ada_really_inline bool url_aggregator::includes_credentials() const noexcept {
  ada_log("url_aggregator::includes_credentials");
  if (has_authority()) { return true; }
  if (buffer[components.username_end] == ':' && components.username_end + 1 < components.host_start) { return true; }
  return false;
}

inline bool url_aggregator::cannot_have_credentials_or_port() const {
  ada_log("url_aggregator::cannot_have_credentials_or_port");
  return type == ada::scheme::type::FILE || components.host_start == components.host_end;
}

[[nodiscard]] ada_really_inline const ada::url_components& url_aggregator::get_components() const noexcept {
  return components;
}

inline bool ada::url_aggregator::has_authority() const noexcept {
  ada_log("url_aggregator::has_authority");
  return (components.protocol_end + 2 <= buffer.size()) && helpers::substring(buffer, components.protocol_end, components.protocol_end + 2) == "//";
}

inline void ada::url_aggregator::add_authority_slashes_if_needed() noexcept {
  // Protocol setter will insert `http:` to the URL. It is up to hostname setter to insert
  // `//` initially to the buffer, since it depends on the hostname existance.
  if (has_authority()) { return; }
  // Performance: the common case is components.protocol_end == buffer.size()
  // Optimization opportunity: in many cases, the "//" is part of the input and the
  // insert could be fused with another insert.
  buffer.insert(components.protocol_end, "//");
  components.username_end += 2;
  components.host_start += 2;
  components.host_end += 2;
  components.pathname_start += 2;
  if (components.search_start != url_components::omitted) { components.search_start += 2; }
  if (components.hash_start != url_components::omitted) { components.hash_start += 2; }
}

inline void ada::url_aggregator::reserve(uint32_t capacity) {
  buffer.reserve(capacity);
}

std::string& ada::url_aggregator::get_buffer() noexcept {
  return buffer;
}

}

#endif // ADA_URL_AGGREGATOR_INL_H
