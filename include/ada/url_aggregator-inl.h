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
#include "ada/unicode-inl.h"
#include "ada/url_aggregator.h"
#include "ada/url_components.h"
#include "ada/scheme.h"
#include "ada/log.h"

#include <optional>
#include <string_view>

namespace ada {

inline void url_aggregator::update_base_authority(
    std::string_view base_buffer, const ada::url_components &base) {
  std::string_view input = base_buffer.substr(
      base.protocol_end, base.host_start - base.protocol_end);
  ada_log("url_aggregator::update_base_authority ", input);

  bool input_starts_with_dash = checkers::begins_with(input, "//");
  uint32_t diff = components.host_start - components.protocol_end;

  buffer.erase(components.protocol_end,
               components.host_start - components.protocol_end);
  components.username_end = components.protocol_end;

  if (input_starts_with_dash) {
    input.remove_prefix(2);
    diff += 2;  // add "//"
    buffer.insert(components.protocol_end, "//");
    components.username_end += 2;
  }

  size_t password_delimiter = input.find(':');

  // Check if input contains both username and password by checking the
  // delimiter: ":" A typical input that contains authority would be "user:pass"
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
    components.username_end =
        components.protocol_end + diff + uint32_t(input.size());
    diff += uint32_t(input.size());
  }

  components.host_start += diff;

  if (buffer.size() > base.host_start && buffer[base.host_start] != '@') {
    buffer.insert(components.host_start, "@");
    diff++;
  }
  components.host_end += diff;
  components.pathname_start += diff;
  if (components.search_start != url_components::omitted) {
    components.search_start += diff;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += diff;
  }
}

inline void url_aggregator::update_unencoded_base_hash(std::string_view input) {
  ada_log("url_aggregator::update_unencoded_base_hash ", input, " [",
          input.size(), " bytes], buffer is '", buffer, "' [", buffer.size(),
          " bytes] components.hash_start = ", components.hash_start);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (components.hash_start != url_components::omitted) {
    buffer.resize(components.hash_start);
  }
  components.hash_start = uint32_t(buffer.size());
  buffer += "#";
  bool encoding_required = unicode::percent_encode<true>(
      input, ada::character_sets::FRAGMENT_PERCENT_ENCODE, buffer);
  // When encoding_required is false, then buffer is left unchanged, and percent
  // encoding was not deemed required.
  if (!encoding_required) {
    buffer.append(input);
  }
  ada_log("url_aggregator::update_unencoded_base_hash final buffer is '",
          buffer, "' [", buffer.size(), " bytes]");
  ADA_ASSERT_TRUE(validate());
}

ada_really_inline uint32_t url_aggregator::replace_and_resize(
    uint32_t start, uint32_t end, std::string_view input) {
  uint32_t current_length = end - start;
  uint32_t input_size = uint32_t(input.size());
  uint32_t new_difference = input_size - current_length;

  if (current_length == 0) {
    buffer.insert(start, input);
  } else if (input_size == current_length) {
    buffer.replace(start, input_size, input);
  } else if (input_size < current_length) {
    buffer.erase(start, current_length - input_size);
    buffer.replace(start, input_size, input);
  } else {
    buffer.replace(start, current_length, input.substr(0, current_length));
    buffer.insert(start + current_length, input.substr(current_length));
  }

  return new_difference;
}

inline void url_aggregator::update_base_hostname(const std::string_view input) {
  ada_log("url_aggregator::update_base_hostname ", input, " [", input.size(),
          " bytes], buffer is '", buffer, "' [", buffer.size(), " bytes]");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));

  // This next line is required for when parsing a URL like `foo://`
  add_authority_slashes_if_needed();

  bool has_credentials = components.protocol_end + 2 < components.host_start;
  uint32_t new_difference =
      replace_and_resize(components.host_start, components.host_end, input);

  if (has_credentials) {
    buffer.insert(components.host_start, "@");
    new_difference++;
  }
  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != url_components::omitted) {
    components.search_start += new_difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += new_difference;
  }
  ADA_ASSERT_TRUE(validate());
}

[[nodiscard]] ada_really_inline uint32_t
url_aggregator::get_pathname_length() const noexcept {
  ada_log("url_aggregator::get_pathname_length");
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) {
    ending_index = components.search_start;
  } else if (components.hash_start != url_components::omitted) {
    ending_index = components.hash_start;
  }
  return ending_index - components.pathname_start;
}

[[nodiscard]] ada_really_inline bool url_aggregator::is_at_path()
    const noexcept {
  return buffer.size() == components.pathname_start;
}

inline void url_aggregator::update_base_search(std::string_view input) {
  ada_log("url_aggregator::update_base_search ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (input.empty()) {
    clear_search();
    return;
  }

  if (input[0] == '?') {
    input.remove_prefix(1);
  }

  if (components.hash_start == url_components::omitted) {
    if (components.search_start == url_components::omitted) {
      components.search_start = uint32_t(buffer.size());
      buffer += "?";
    } else {
      buffer.resize(components.search_start + 1);
    }

    buffer.append(input);
  } else {
    if (components.search_start == url_components::omitted) {
      components.search_start = components.hash_start;
    } else {
      buffer.erase(components.search_start,
                   components.hash_start - components.search_start);
      components.hash_start = components.search_start;
    }

    buffer.insert(components.search_start, "?");
    buffer.insert(components.search_start + 1, input);
    components.hash_start += uint32_t(input.size() + 1);  // Do not forget `?`
  }

  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::update_base_search(
    std::string_view input, const uint8_t query_percent_encode_set[]) {
  ada_log("url_aggregator::update_base_search ", input,
          " with encoding parameter ", to_string(), "\n", to_diagram());
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));

  if (components.hash_start == url_components::omitted) {
    if (components.search_start == url_components::omitted) {
      components.search_start = uint32_t(buffer.size());
      buffer += "?";
    } else {
      buffer.resize(components.search_start + 1);
    }

    bool encoding_required =
        unicode::percent_encode<true>(input, query_percent_encode_set, buffer);
    // When encoding_required is false, then buffer is left unchanged, and
    // percent encoding was not deemed required.
    if (!encoding_required) {
      buffer.append(input);
    }
  } else {
    if (components.search_start == url_components::omitted) {
      components.search_start = components.hash_start;
    } else {
      buffer.erase(components.search_start,
                   components.hash_start - components.search_start);
      components.hash_start = components.search_start;
    }

    buffer.insert(components.search_start, "?");
    size_t idx =
        ada::unicode::percent_encode_index(input, query_percent_encode_set);
    if (idx == input.size()) {
      buffer.insert(components.search_start + 1, input);
      components.hash_start += uint32_t(input.size() + 1);  // Do not forget `?`
    } else {
      buffer.insert(components.search_start + 1, input, 0, idx);
      input.remove_prefix(idx);
      // We only create a temporary string if we need percent encoding and
      // we attempt to create as small a temporary string as we can.
      std::string encoded =
          ada::unicode::percent_encode(input, query_percent_encode_set);
      buffer.insert(components.search_start + idx + 1, encoded);
      components.hash_start +=
          uint32_t(encoded.size() + idx + 1);  // Do not forget `?`
    }
  }

  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::update_base_pathname(const std::string_view input) {
  ada_log("url_aggregator::update_base_pathname '", input, "' [", input.size(),
          " bytes] \n", to_diagram());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  ADA_ASSERT_TRUE(validate());

  const bool begins_with_dashdash = checkers::begins_with(input, "//");
  if (!begins_with_dashdash && has_dash_dot()) {
    ada_log("url_aggregator::update_base_pathname has /.: \n", to_diagram());
    // We must delete the ./
    delete_dash_dot();
  }

  if (begins_with_dashdash && !has_opaque_path && !has_authority() &&
      !has_dash_dot()) {
    // If url's host is null, url does not have an opaque path, url's path's
    // size is greater than 1, then append U+002F (/) followed by U+002E (.) to
    // output.
    buffer.insert(components.pathname_start, "/.");
    components.pathname_start += 2;
  }

  uint32_t difference = replace_and_resize(
      components.pathname_start,
      components.pathname_start + get_pathname_length(), input);
  if (components.search_start != url_components::omitted) {
    components.search_start += difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += difference;
  }
  ada_log("url_aggregator::update_base_pathname end '", input, "' [",
          input.size(), " bytes] \n", to_diagram());
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::append_base_pathname(const std::string_view input) {
  ada_log("url_aggregator::append_base_pathname ", input, " ", to_string(),
          "\n", to_diagram());
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
#if ADA_DEVELOPMENT_CHECKS
  // computing the expected password.
  std::string path_expected(get_pathname());
  path_expected.append(input);
#endif  // ADA_DEVELOPMENT_CHECKS
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) {
    ending_index = components.search_start;
  } else if (components.hash_start != url_components::omitted) {
    ending_index = components.hash_start;
  }
  buffer.insert(ending_index, input);

  if (components.search_start != url_components::omitted) {
    components.search_start += uint32_t(input.size());
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += uint32_t(input.size());
  }
#if ADA_DEVELOPMENT_CHECKS
  std::string path_after = std::string(get_pathname());
  ADA_ASSERT_EQUAL(
      path_expected, path_after,
      "append_base_pathname problem after inserting " + std::string(input));
#endif  // ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::update_base_username(const std::string_view input) {
  ada_log("url_aggregator::update_base_username '", input, "' ", to_string(),
          "\n", to_diagram());
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));

  add_authority_slashes_if_needed();

  bool has_password = has_non_empty_password();
  bool host_starts_with_at = buffer.size() > components.host_start &&
                             buffer[components.host_start] == '@';
  uint32_t diff = replace_and_resize(components.protocol_end + 2,
                                     components.username_end, input);

  components.username_end += diff;
  components.host_start += diff;

  if (!input.empty() && !host_starts_with_at) {
    buffer.insert(components.host_start, "@");
    diff++;
  } else if (input.empty() && host_starts_with_at && !has_password) {
    // Input is empty, there is no password, and we need to remove "@" from
    // hostname
    buffer.erase(components.host_start, 1);
    diff--;
  }

  components.host_end += diff;
  components.pathname_start += diff;
  if (components.search_start != url_components::omitted) {
    components.search_start += diff;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += diff;
  }
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::append_base_username(const std::string_view input) {
  ada_log("url_aggregator::append_base_username ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
#if ADA_DEVELOPMENT_CHECKS
  // computing the expected password.
  std::string username_expected(get_username());
  username_expected.append(input);
#endif  // ADA_DEVELOPMENT_CHECKS
  add_authority_slashes_if_needed();

  // If input is empty, do nothing.
  if (input.empty()) {
    return;
  }

  uint32_t difference = uint32_t(input.size());
  buffer.insert(components.username_end, input);
  components.username_end += difference;
  components.host_start += difference;

  if (buffer[components.host_start] != '@' &&
      components.host_start != components.host_end) {
    buffer.insert(components.host_start, "@");
    difference++;
  }

  components.host_end += difference;
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) {
    components.search_start += difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += difference;
  }
#if ADA_DEVELOPMENT_CHECKS
  std::string username_after(get_username());
  ADA_ASSERT_EQUAL(
      username_expected, username_after,
      "append_base_username problem after inserting " + std::string(input));
#endif  // ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::clear_password() {
  ada_log("url_aggregator::clear_password ", to_string(), "\n", to_diagram());
  ADA_ASSERT_TRUE(validate());
  if (!has_password()) {
    return;
  }

  uint32_t diff = components.host_start - components.username_end;
  buffer.erase(components.username_end, diff);
  components.host_start -= diff;
  components.host_end -= diff;
  components.pathname_start -= diff;
  if (components.search_start != url_components::omitted) {
    components.search_start -= diff;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start -= diff;
  }
}

inline void url_aggregator::update_base_password(const std::string_view input) {
  ada_log("url_aggregator::update_base_password ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));

  add_authority_slashes_if_needed();

  // TODO: Optimization opportunity. Merge the following removal functions.
  if (input.empty()) {
    clear_password();

    // Remove username too, if it is empty.
    if (!has_non_empty_username()) {
      update_base_username("");
    }

    return;
  }

  bool password_exists = has_password();
  uint32_t difference = uint32_t(input.size());

  if (password_exists) {
    uint32_t current_length =
        components.host_start - components.username_end - 1;
    buffer.erase(components.username_end + 1, current_length);
    difference -= current_length;
  } else {
    buffer.insert(components.username_end, ":");
    difference++;
  }

  buffer.insert(components.username_end + 1, input);
  components.host_start += difference;

  // The following line is required to add "@" to hostname. When updating
  // password if hostname does not start with "@", it is "update_base_password"s
  // responsibility to set it.
  if (buffer[components.host_start] != '@') {
    buffer.insert(components.host_start, "@");
    difference++;
  }

  components.host_end += difference;
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) {
    components.search_start += difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += difference;
  }
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::append_base_password(const std::string_view input) {
  ada_log("url_aggregator::append_base_password ", input, " ", to_string(),
          "\n", to_diagram());
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
#if ADA_DEVELOPMENT_CHECKS
  // computing the expected password.
  std::string password_expected = std::string(get_password());
  password_expected.append(input);
#endif  // ADA_DEVELOPMENT_CHECKS
  add_authority_slashes_if_needed();

  // If input is empty, do nothing.
  if (input.empty()) {
    return;
  }

  uint32_t difference = uint32_t(input.size());
  if (has_password()) {
    buffer.insert(components.host_start, input);
  } else {
    difference++;  // Increment for ":"
    buffer.insert(components.username_end, ":");
    buffer.insert(components.username_end + 1, input);
  }
  components.host_start += difference;

  // The following line is required to add "@" to hostname. When updating
  // password if hostname does not start with "@", it is "append_base_password"s
  // responsibility to set it.
  if (buffer[components.host_start] != '@') {
    buffer.insert(components.host_start, "@");
    difference++;
  }

  components.host_end += difference;
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) {
    components.search_start += difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += difference;
  }
#if ADA_DEVELOPMENT_CHECKS
  std::string password_after(get_password());
  ADA_ASSERT_EQUAL(
      password_expected, password_after,
      "append_base_password problem after inserting " + std::string(input));
#endif  // ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::update_base_port(uint32_t input) {
  ada_log("url_aggregator::update_base_port");
  ADA_ASSERT_TRUE(validate());
  if (input == url_components::omitted) {
    clear_port();
    return;
  }
  // calling std::to_string(input.value()) is unfortunate given that the port
  // value is probably already available as a string.
  std::string value = helpers::concat(":", std::to_string(input));
  uint32_t difference = uint32_t(value.size());

  if (components.port != url_components::omitted) {
    difference -= components.pathname_start - components.host_end;
    buffer.erase(components.host_end,
                 components.pathname_start - components.host_end);
  }

  buffer.insert(components.host_end, value);
  components.pathname_start += difference;
  if (components.search_start != url_components::omitted) {
    components.search_start += difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += difference;
  }
  components.port = input;
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::clear_port() {
  ada_log("url_aggregator::clear_port");
  ADA_ASSERT_TRUE(validate());
  if (components.port == url_components::omitted) {
    return;
  }
  uint32_t length = components.pathname_start - components.host_end;
  buffer.erase(components.host_end, length);
  components.pathname_start -= length;
  if (components.search_start != url_components::omitted) {
    components.search_start -= length;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start -= length;
  }
  components.port = url_components::omitted;
  ADA_ASSERT_TRUE(validate());
}

[[nodiscard]] inline uint32_t url_aggregator::retrieve_base_port() const {
  ada_log("url_aggregator::retrieve_base_port");
  return components.port;
}

inline void url_aggregator::clear_search() {
  ada_log("url_aggregator::clear_search");
  ADA_ASSERT_TRUE(validate());
  if (components.search_start == url_components::omitted) {
    return;
  }

  if (components.hash_start == url_components::omitted) {
    buffer.resize(components.search_start);
  } else {
    buffer.erase(components.search_start,
                 components.hash_start - components.search_start);
    components.hash_start = components.search_start;
  }

  components.search_start = url_components::omitted;

#if ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_EQUAL(get_search(), "",
                   "search should have been cleared on buffer=" + buffer +
                       " with " + components.to_string() + "\n" + to_diagram());
#endif
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::clear_hash() {
  ada_log("url_aggregator::clear_hash");
  ADA_ASSERT_TRUE(validate());
  if (components.hash_start == url_components::omitted) {
    return;
  }
  buffer.resize(components.hash_start);
  components.hash_start = url_components::omitted;

#if ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_EQUAL(get_hash(), "",
                   "hash should have been cleared on buffer=" + buffer +
                       " with " + components.to_string() + "\n" + to_diagram());
#endif
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::clear_pathname() {
  ada_log("url_aggregator::clear_pathname");
  ADA_ASSERT_TRUE(validate());
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) {
    ending_index = components.search_start;
  } else if (components.hash_start != url_components::omitted) {
    ending_index = components.hash_start;
  }
  uint32_t pathname_length = ending_index - components.pathname_start;
  buffer.erase(components.pathname_start, pathname_length);
  uint32_t difference = pathname_length;
  if (components.pathname_start == components.host_end + 2 &&
      buffer[components.host_end] == '/' &&
      buffer[components.host_end + 1] == '.') {
    components.pathname_start -= 2;
    buffer.erase(components.host_end, 2);
    difference += 2;
  }
  if (components.search_start != url_components::omitted) {
    components.search_start -= difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start -= difference;
  }
  ada_log("url_aggregator::clear_pathname completed, running checks...");
#if ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_EQUAL(get_pathname(), "",
                   "pathname should have been cleared on buffer=" + buffer +
                       " with " + components.to_string() + "\n" + to_diagram());
#endif
  ADA_ASSERT_TRUE(validate());
  ada_log("url_aggregator::clear_pathname completed, running checks... ok");
}

inline void url_aggregator::clear_hostname() {
  ada_log("url_aggregator::clear_hostname");
  ADA_ASSERT_TRUE(validate());
  if (!has_authority()) {
    return;
  }
  ADA_ASSERT_TRUE(has_authority());

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
  if (components.search_start != url_components::omitted) {
    components.search_start -= hostname_length;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start -= hostname_length;
  }
#if ADA_DEVELOPMENT_CHECKS
  ADA_ASSERT_EQUAL(get_hostname(), "",
                   "hostname should have been cleared on buffer=" + buffer +
                       " with " + components.to_string() + "\n" + to_diagram());
#endif
  ADA_ASSERT_TRUE(has_authority());
  ADA_ASSERT_EQUAL(has_empty_hostname(), true,
                   "hostname should have been cleared on buffer=" + buffer +
                       " with " + components.to_string() + "\n" + to_diagram());
  ADA_ASSERT_TRUE(validate());
}

[[nodiscard]] inline bool url_aggregator::has_hash() const noexcept {
  ada_log("url_aggregator::has_hash");
  return components.hash_start != url_components::omitted;
}

[[nodiscard]] inline bool url_aggregator::has_search() const noexcept {
  ada_log("url_aggregator::has_search");
  return components.search_start != url_components::omitted;
}

ada_really_inline bool url_aggregator::has_credentials() const noexcept {
  ada_log("url_aggregator::has_credentials");
  return has_non_empty_username() || has_non_empty_password();
}

inline bool url_aggregator::cannot_have_credentials_or_port() const {
  ada_log("url_aggregator::cannot_have_credentials_or_port");
  return type == ada::scheme::type::FILE ||
         components.host_start == components.host_end;
}

[[nodiscard]] ada_really_inline const ada::url_components &
url_aggregator::get_components() const noexcept {
  return components;
}

[[nodiscard]] inline bool ada::url_aggregator::has_authority() const noexcept {
  ada_log("url_aggregator::has_authority");
  // Performance: instead of doing this potentially expensive check, we could
  // have a boolean in the struct.
  return components.protocol_end + 2 <= components.host_start &&
         helpers::substring(buffer, components.protocol_end,
                            components.protocol_end + 2) == "//";
}

inline void ada::url_aggregator::add_authority_slashes_if_needed() noexcept {
  ada_log("url_aggregator::add_authority_slashes_if_needed");
  ADA_ASSERT_TRUE(validate());
  // Protocol setter will insert `http:` to the URL. It is up to hostname setter
  // to insert
  // `//` initially to the buffer, since it depends on the hostname existence.
  if (has_authority()) {
    return;
  }
  // Performance: the common case is components.protocol_end == buffer.size()
  // Optimization opportunity: in many cases, the "//" is part of the input and
  // the insert could be fused with another insert.
  buffer.insert(components.protocol_end, "//");
  components.username_end += 2;
  components.host_start += 2;
  components.host_end += 2;
  components.pathname_start += 2;
  if (components.search_start != url_components::omitted) {
    components.search_start += 2;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += 2;
  }
  ADA_ASSERT_TRUE(validate());
}

inline void ada::url_aggregator::reserve(uint32_t capacity) {
  buffer.reserve(capacity);
}

inline bool url_aggregator::has_non_empty_username() const noexcept {
  ada_log("url_aggregator::has_non_empty_username");
  return components.protocol_end + 2 < components.username_end;
}

inline bool url_aggregator::has_non_empty_password() const noexcept {
  ada_log("url_aggregator::has_non_empty_password");
  return components.host_start - components.username_end > 0;
}

inline bool url_aggregator::has_password() const noexcept {
  ada_log("url_aggregator::has_password");
  // This function does not care about the length of the password
  return components.host_start > components.username_end &&
         buffer[components.username_end] == ':';
}

inline bool url_aggregator::has_empty_hostname() const noexcept {
  if (!has_hostname()) {
    return false;
  }
  if (components.host_start == components.host_end) {
    return true;
  }
  if (components.host_end > components.host_start + 1) {
    return false;
  }
  return components.username_end != components.host_start;
}

inline bool url_aggregator::has_hostname() const noexcept {
  return has_authority();
}

inline bool url_aggregator::has_port() const noexcept {
  ada_log("url_aggregator::has_port");
  // A URL cannot have a username/password/port if its host is null or the empty
  // string, or its scheme is "file".
  return has_hostname() && components.pathname_start != components.host_end;
}

[[nodiscard]] inline bool url_aggregator::has_dash_dot() const noexcept {
  // If url's host is null, url does not have an opaque path, url's path's size
  // is greater than 1, and url's path[0] is the empty string, then append
  // U+002F (/) followed by U+002E (.) to output.
  ada_log("url_aggregator::has_dash_dot");
#if ADA_DEVELOPMENT_CHECKS
  // If pathname_start and host_end are exactly two characters apart, then we
  // either have a one-digit port such as http://test.com:5?param=1 or else we
  // have a /.: sequence such as "non-spec:/.//". We test that this is the case.
  if (components.pathname_start == components.host_end + 2) {
    ADA_ASSERT_TRUE((buffer[components.host_end] == '/' &&
                     buffer[components.host_end + 1] == '.') ||
                    (buffer[components.host_end] == ':' &&
                     checkers::is_digit(buffer[components.host_end + 1])));
  }
  if (components.pathname_start == components.host_end + 2 &&
      buffer[components.host_end] == '/' &&
      buffer[components.host_end + 1] == '.') {
    ADA_ASSERT_TRUE(components.pathname_start + 1 < buffer.size());
    ADA_ASSERT_TRUE(buffer[components.pathname_start] == '/');
    ADA_ASSERT_TRUE(buffer[components.pathname_start + 1] == '/');
  }
#endif
  // Performance: it should be uncommon for components.pathname_start ==
  // components.host_end + 2 to be true. So we put this check first in the
  // sequence. Most times, we do not have an opaque path. Checking for '/.' is
  // more expensive, but should be uncommon.
  return components.pathname_start == components.host_end + 2 &&
         !has_opaque_path && buffer[components.host_end] == '/' &&
         buffer[components.host_end + 1] == '.';
}

[[nodiscard]] inline std::string_view url_aggregator::get_href() const noexcept
    ada_lifetime_bound {
  ada_log("url_aggregator::get_href");
  return buffer;
}

ada_really_inline size_t url_aggregator::parse_port(
    std::string_view view, bool check_trailing_content) noexcept {
  ada_log("url_aggregator::parse_port('", view, "') ", view.size());
  if (!view.empty() && view[0] == '-') {
    ada_log("parse_port: view[0] == '0' && view.size() > 1");
    is_valid = false;
    return 0;
  }
  uint16_t parsed_port{};
  auto r = std::from_chars(view.data(), view.data() + view.size(), parsed_port);
  if (r.ec == std::errc::result_out_of_range) {
    ada_log("parse_port: r.ec == std::errc::result_out_of_range");
    is_valid = false;
    return 0;
  }
  ada_log("parse_port: ", parsed_port);
  const size_t consumed = size_t(r.ptr - view.data());
  ada_log("parse_port: consumed ", consumed);
  if (check_trailing_content) {
    is_valid &=
        (consumed == view.size() || view[consumed] == '/' ||
         view[consumed] == '?' || (is_special() && view[consumed] == '\\'));
  }
  ada_log("parse_port: is_valid = ", is_valid);
  if (is_valid) {
    ada_log("parse_port", r.ec == std::errc());
    // scheme_default_port can return 0, and we should allow 0 as a base port.
    auto default_port = scheme_default_port();
    bool is_port_valid = (default_port == 0 && parsed_port == 0) ||
                         (default_port != parsed_port);
    if (r.ec == std::errc() && is_port_valid) {
      update_base_port(parsed_port);
    } else {
      clear_port();
    }
  }
  return consumed;
}

inline void url_aggregator::set_protocol_as_file() {
  ada_log("url_aggregator::set_protocol_as_file ");
  ADA_ASSERT_TRUE(validate());
  type = ada::scheme::type::FILE;
  // next line could overflow but unsigned arithmetic has well-defined
  // overflows.
  uint32_t new_difference = 5 - components.protocol_end;

  if (buffer.empty()) {
    buffer.append("file:");
  } else {
    buffer.erase(0, components.protocol_end);
    buffer.insert(0, "file:");
  }
  components.protocol_end = 5;

  // Update the rest of the components.
  components.username_end += new_difference;
  components.host_start += new_difference;
  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != url_components::omitted) {
    components.search_start += new_difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += new_difference;
  }
  ADA_ASSERT_TRUE(validate());
}

inline std::ostream &operator<<(std::ostream &out,
                                const ada::url_aggregator &u) {
  return out << u.to_string();
}
}  // namespace ada

#endif  // ADA_URL_AGGREGATOR_INL_H
