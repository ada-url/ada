/**
 * @file url_aggregator-inl.h
 * @brief Inline functions for url aggregator
 */
#ifndef ADA_URL_AGGREGATOR_INL_H
#define ADA_URL_AGGREGATOR_INL_H

#include "ada/character_sets.h"
#include "ada/character_sets-inl.h"
#include "ada/checkers-inl.h"
#include "ada/helpers.h"
#include "ada/unicode.h"
#include "ada/url_aggregator.h"
#include "ada/url_components.h"
#include "ada/scheme.h"
#include "ada/log.h"

#include <optional>
#include <string_view>

namespace ada {

inline void url_aggregator::update_base_authority(std::string_view base_buffer, const ada::url_components& base) {
  std::string_view input = base_buffer.substr(base.protocol_end, base.host_start - base.protocol_end);
  ada_log("url_aggregator::update_base_authority ", input);

  bool input_starts_with_dash = checkers::begins_with(input, "//");
  uint32_t diff = components.host_start - components.protocol_end;

  buffer.erase(components.protocol_end, components.host_start - components.protocol_end);
  components.username_end = components.protocol_end;

  if (input_starts_with_dash) {
    input.remove_prefix(2);
    diff += 2; // add "//"
    buffer.insert(components.protocol_end, "//");
    components.username_end += 2;
  }

  size_t password_delimiter = input.find(':');

  // Check if input contains both username and password by checking the delimiter: ":"
  // A typical input that contains authority would be "user:pass"
  if (password_delimiter != std::string_view::npos) {
    // Insert both username and password
    std::string_view username = input.substr(0, password_delimiter);
    std::string_view password = input.substr(password_delimiter + 1);

    buffer.insert(components.protocol_end + diff, username);
    diff += uint32_t(username.size());
    buffer.insert(components.protocol_end + diff, ":");
    components.username_end = components.protocol_end + diff;
    buffer.insert(components.protocol_end + diff + 1, password);
    diff += uint32_t(password.size()) + 1;
  } else if (!input.empty()) {
    // Insert only username
    buffer.insert(components.protocol_end + diff, input);
    components.username_end = components.protocol_end + diff + uint32_t(input.size());
    diff += uint32_t(input.size());
  }

  components.host_start += diff;

  if (buffer.size() > base.host_start && buffer[base.host_start] != '@') {
    buffer.insert(components.host_start, "@");
    diff++;
  }
  components.host_end += diff;
  components.pathname_start += diff;
  if (components.search_start != url_components::omitted) { components.search_start += diff; }
  if (components.hash_start != url_components::omitted) { components.hash_start += diff; }
}

inline void url_aggregator::update_unencoded_base_hash(std::string_view input) {
  ada_log("url_aggregator::update_unencoded_base_hash ", input, " [", input.size(), " bytes], buffer is '", buffer, "' [", buffer.size(), " bytes] components.hash_start = ", components.hash_start);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (components.hash_start != url_components::omitted) {
    buffer.resize(components.hash_start);
  }
  components.hash_start = uint32_t(buffer.size());
  buffer += "#";
  bool encoding_required = unicode::percent_encode<true>(input, ada::character_sets::FRAGMENT_PERCENT_ENCODE, buffer);
  // When encoding_required is false, then buffer is left unchanged, and percent encoding was not deemed required.
  if (!encoding_required) { buffer.append(input); }
  ada_log("url_aggregator::update_unencoded_base_hash final buffer is '", buffer, "' [", buffer.size(), " bytes]");
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::update_base_hostname(const std::string_view input) {
  ada_log("url_aggregator::update_base_hostname ", input, " [", input.size(), " bytes], buffer is '", buffer, "' [", buffer.size()," bytes]");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));

  // This next line is required for when parsing a URL like `foo://`
  add_authority_slashes_if_needed();

  bool has_credential = components.protocol_end + 2 < components.host_start;
  uint32_t current_length = components.host_end - components.host_start;
  uint32_t new_difference = uint32_t(input.size()) - current_length;
  // The common case is current_length == 0.
  buffer.erase(components.host_start, current_length);

  uint32_t host_start = components.host_start;
  // The common case is components.host_start == buffer.size().
  if (has_credential) {
    buffer.insert(host_start, "@");
    host_start++;
    new_difference++;
  }
  buffer.insert(host_start, input);
  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != url_components::omitted) { components.search_start += new_difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += new_difference; }
  ADA_ASSERT_TRUE(validate());
}

ada_really_inline uint32_t url_aggregator::get_pathname_length() const noexcept {
  ada_log("url_aggregator::get_pathname_length");
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) { ending_index = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  return ending_index - components.pathname_start;
}

[[nodiscard]] ada_really_inline bool url_aggregator::is_at_path() const noexcept {
  return buffer.size() == components.pathname_start;
}

inline void url_aggregator::update_base_search(std::string_view input) {
  ada_log("url_aggregator::update_base_search ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
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

  uint32_t input_size = uint32_t(input.size());
  components.search_start = components.pathname_start + get_pathname_length();
  // The common case here is components.search_start == buffer.size().

  if (input[0] != '?') {
    // If input does not start with "?", we need to add it.
    buffer.insert(components.search_start, helpers::concat("?", input));
    input_size++;
  } else {
    buffer.insert(components.search_start, input);
  }
  if (components.hash_start != url_components::omitted) { components.hash_start += input_size; }
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::update_base_search(std::string_view input, const uint8_t query_percent_encode_set[]) {
  ada_log("url_aggregator::update_base_search ", input, " with encoding parameter ", to_string(), "\n", to_diagram());
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
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
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::update_base_pathname(const std::string_view input) {
  ada_log("url_aggregator::update_base_pathname '", input, "' [", input.size(), " bytes] \n", to_diagram());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  ADA_ASSERT_TRUE(validate());
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
  ada_log("url_aggregator::update_base_pathname end '", input, "' [", input.size(), " bytes] \n", to_diagram());
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::append_base_pathname(const std::string_view input) {
  ada_log("url_aggregator::append_base_pathname ", input, " ", to_string(), "\n", to_diagram());
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
#if ADA_DEVELOPMENT_CHECKS
  // computing the expected password.
  std::string path_expected = std::string(get_pathname());
  path_expected.append(input);
#endif // ADA_DEVELOPMENT_CHECKS
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) { ending_index = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  buffer.insert(ending_index, input);

  uint32_t difference = uint32_t(input.size());
  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
#if ADA_DEVELOPMENT_CHECKS
  std::string path_after = std::string(get_pathname());
  ADA_ASSERT_EQUAL(path_expected, path_after, "append_base_pathname problem after inserting "+std::string(input));
#endif // ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::update_base_username(const std::string_view input) {
  ada_log("url_aggregator::update_base_username '", input, "' ", to_string(), "\n", to_diagram());
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  add_authority_slashes_if_needed();

  uint32_t username_start = components.protocol_end + 2;
  uint32_t diff = uint32_t(input.size());

  if (username_start == components.username_end) {
    buffer.insert(username_start, input);
  } else {
    uint32_t current_length = components.username_end - username_start;
    buffer.erase(username_start, current_length);
    buffer.insert(username_start, input);
    diff -= current_length;
  }

  components.username_end += diff;
  components.host_start += diff;

  // Add missing "@" to host start.
  if (!input.empty() && buffer[components.host_start] != '@') {
    buffer.insert(components.host_start, "@");
    diff++;
  }

  components.host_end += diff;
  components.pathname_start += diff;
  if (components.search_start != url_components::omitted) { components.search_start += diff; }
  if (components.hash_start != url_components::omitted) { components.hash_start += diff; }
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::append_base_username(const std::string_view input) {
  ada_log("url_aggregator::append_base_username ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
#if ADA_DEVELOPMENT_CHECKS
  // computing the expected password.
  std::string username_expected = std::string(get_username());
  username_expected.append(input);
#endif // ADA_DEVELOPMENT_CHECKS
  add_authority_slashes_if_needed();

  // If input is empty, do nothing.
  if (input.empty()) { return; }

  uint32_t difference = uint32_t(input.size());
  buffer.insert(components.username_end, input);
  components.username_end += uint32_t(input.size());
  components.host_start += difference;

  if (buffer[components.host_start] != '@' && components.host_start != components.host_end) {
    buffer.insert(components.host_start, "@");
    difference++;
  }

  components.host_end += difference;
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
#if ADA_DEVELOPMENT_CHECKS
  std::string username_after = std::string(get_username());
  ADA_ASSERT_EQUAL(username_expected, username_after, "append_base_username problem after inserting "+std::string(input));
#endif // ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::clear_base_password() {
  ada_log("url_aggregator::clear_base_password ", to_string(), "\n", to_diagram());
  ADA_ASSERT_TRUE(validate());
  if (!has_password()) { return; }

  uint32_t diff = components.host_start - components.username_end;
  buffer.erase(components.username_end, diff);
  components.host_start -= diff;
  components.host_end -= diff;
  components.pathname_start -= diff;
  if (components.search_start != url_components::omitted) { components.search_start -= diff; }
  if (components.hash_start != url_components::omitted) { components.hash_start -= diff; }
}

inline void url_aggregator::update_base_password(const std::string_view input) {
  ada_log("url_aggregator::update_base_password ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));

  add_authority_slashes_if_needed();

  if (input.empty()) {
    clear_base_password();
    return;
  }

  bool password_exists = has_password();
  uint32_t difference = uint32_t(input.size());

  if (password_exists) {
    uint32_t password_end = components.host_start;
    if (components.host_start != components.host_end) { password_end--; }
    uint32_t current_length = password_end - components.username_end + 1;
    buffer.erase(components.username_end + 1, current_length);
    difference -= current_length;
  } else {
    buffer.insert(components.username_end, ":");
    difference++;
  }

  buffer.insert(components.username_end + 1, input);
  components.host_start += difference;

  // The following line is required to add "@" to hostname. When updating password if hostname
  // does not start with "@", it is "update_base_password"s responsibility to set it.
  if (buffer[components.host_start] != '@') {
    buffer.insert(components.host_start, "@");
    difference++;
  }

  components.host_end += difference;
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::append_base_password(const std::string_view input) {
  ada_log("url_aggregator::append_base_password ", input, " ", to_string(), "\n", to_diagram());
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
#if ADA_DEVELOPMENT_CHECKS
  // computing the expected password.
  std::string password_expected = std::string(get_password());
  password_expected.append(input);
#endif // ADA_DEVELOPMENT_CHECKS
  add_authority_slashes_if_needed();

  // If input is empty, do nothing.
  if (input.empty()) { return; }

  uint32_t difference = uint32_t(input.size());
  if (has_password()) {
    buffer.insert(components.host_start, input);
  } else {
    difference++; // Increment for ":"
    buffer.insert(components.username_end, ":");
    buffer.insert(components.username_end + 1, input);
  }
  components.host_start += difference;

  // The following line is required to add "@" to hostname. When updating password if hostname
  // does not start with "@", it is "append_base_password"s responsibility to set it.
  if (buffer[components.host_start] != '@') {
    buffer.insert(components.host_start, "@");
    difference++;
  }

  components.host_end += difference;
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
#if ADA_DEVELOPMENT_CHECKS
  std::string password_after = std::string(get_password());
  ADA_ASSERT_EQUAL(password_expected, password_after, "append_base_password problem after inserting "+std::string(input));
#endif // ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::update_base_port(uint32_t input) {
  ada_log("url_aggregator::update_base_port");
  ADA_ASSERT_TRUE(validate());
  if (input == url_components::omitted) {
    clear_base_port();
    return;
  }
  // calling std::to_string(input.value()) is unfortunate given that the port
  // value is probably already available as a string.
  std::string value = helpers::concat(":", std::to_string(input));
  uint32_t difference = uint32_t(value.size());

  if (components.port != url_components::omitted) {
    difference -= components.pathname_start - components.host_end;
    buffer.erase(components.host_end, components.pathname_start - components.host_end);
  }

  buffer.insert(components.host_end, value);
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) { components.search_start += difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += difference; }
  components.port = input;
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::clear_base_port() {
  ada_log("url_aggregator::clear_base_port");
  ADA_ASSERT_TRUE(validate());
  if (components.port == url_components::omitted) { return; }
  uint32_t length = components.pathname_start - components.host_end;
  buffer.erase(components.host_end, length);
  components.pathname_start -= length;
  if (components.search_start != url_components::omitted) { components.search_start -= length; }
  if (components.hash_start != url_components::omitted) { components.hash_start -= length; }
  components.port = url_components::omitted;
  ADA_ASSERT_TRUE(validate());
}

inline uint32_t url_aggregator::retrieve_base_port() const {
  ada_log("url_aggregator::retrieve_base_port");
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
  ada_log("url_aggregator::clear_base_search");
  ADA_ASSERT_TRUE(validate());
  if (components.search_start == url_components::omitted) { return; }

  if (components.hash_start == url_components::omitted) {
    buffer.resize(components.search_start);
  } else {
    buffer.erase(components.search_start, components.hash_start - components.search_start);
    components.hash_start = components.search_start;
  }

  components.search_start = url_components::omitted;

#if ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_EQUAL(get_search(), "", "search should have been cleared on buffer=" + buffer + " with " + components.to_string() + "\n" + to_diagram());
#endif
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::clear_base_pathname() {
  ada_log("url_aggregator::clear_base_pathname");
  ADA_ASSERT_TRUE(validate());
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) { ending_index = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  uint32_t pathname_length = ending_index - components.pathname_start;
  buffer.erase(components.pathname_start, pathname_length);
  if (components.search_start != url_components::omitted) { components.search_start -= pathname_length; }
  if (components.hash_start != url_components::omitted) { components.hash_start -= pathname_length; }
  ada_log("url_aggregator::clear_base_pathname completed, running checks...");
#if ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_EQUAL(get_pathname(), "", "pathname should have been cleared on buffer=" + buffer + " with " + components.to_string() + "\n" + to_diagram());
#endif
  ADA_ASSERT_TRUE(validate());
  ada_log("url_aggregator::clear_base_pathname completed, running checks... ok");
}

inline void url_aggregator::clear_base_hostname() {
  ada_log("url_aggregator::clear_base_hostname");
  ADA_ASSERT_TRUE(validate());

  uint32_t hostname_length = components.host_end - components.host_start;
  uint32_t start = components.host_start;

  // If hostname starts with "@", we should not remove that character.
  if (hostname_length > 0 && buffer[start] == '@') {
    start++;
    hostname_length--;
  }
  buffer.erase(start, hostname_length);
  components.host_end = start;
  components.pathname_start -= hostname_length;
  if (components.search_start != url_components::omitted) { components.search_start -= hostname_length; }
  if (components.hash_start != url_components::omitted) { components.hash_start -= hostname_length; }
#if ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_EQUAL(get_hostname(), "", "hostname should have been cleared on buffer=" + buffer + " with " + components.to_string() + "\n" + to_diagram());
#endif
  ADA_ASSERT_TRUE(validate());
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
  return has_non_empty_username() || has_non_empty_password();
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
  ada_log("url_aggregator::add_authority_slashes_if_needed");
  ADA_ASSERT_TRUE(validate());
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
  ADA_ASSERT_TRUE(validate());
}

inline void ada::url_aggregator::reserve(uint32_t capacity) {
  buffer.reserve(capacity);
}

inline bool url_aggregator::has_non_empty_username() const {
  ada_log("url_aggregator::has_non_empty_username ");
  /**
   * https://user:pass@example.com:1234/foo/bar?baz#quux
   *       |     |    |          | ^^^^|       |   |
   *       |     |    |          | |   |       |   `----- hash_start
   *       |     |    |          | |   |       `--------- search_start
   *       |     |    |          | |   `----------------- pathname_start
   *       |     |    |          | `--------------------- port
   *       |     |    |          `----------------------- host_end
   *       |     |    `---------------------------------- host_start
   *       |     `--------------------------------------- username_end
   *       `--------------------------------------------- protocol_end
   */
  return components.protocol_end + 2 < components.username_end;
}

inline bool url_aggregator::has_non_empty_password() const {
  ada_log("url_aggregator::has_non_empty_password");
  return components.host_start - components.username_end > 0;
}

inline bool url_aggregator::has_password() const {
  ada_log("url_aggregator::has_password");
  // This function does not care about the length of the password
  return buffer.size() > components.username_end && buffer[components.username_end] == ':';
}

inline bool url_aggregator::has_port() const noexcept {
  ada_log("url_aggregator::has_port");
  return components.pathname_start != components.host_end;
}



inline std::string_view url_aggregator::get_href() const noexcept {
  ada_log("url_aggregator::get_href");
  return buffer;
}
}

#endif // ADA_URL_AGGREGATOR_INL_H
