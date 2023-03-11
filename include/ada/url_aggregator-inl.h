/**
 * @file url_aggregator-inl.h
 * @brief Inline functions for url aggregator
 */
#ifndef ADA_URL_AGGREGATOR_INL_H
#define ADA_URL_AGGREGATOR_INL_H

#include "ada/helpers.h"
#include "ada/url_aggregator.h"
#include "ada/url_components.h"
#include "ada/scheme.h"

#include <optional>

namespace ada {

inline void url_aggregator::update_base_hash(std::string_view input) {
  buffer.resize(components.hash_start);
  components.hash_start = uint32_t(buffer.size());
  buffer += "#";
  buffer += input; // assume already percent encoded
}

inline void url_aggregator::update_unencoded_base_hash(std::string_view input) {
  buffer.resize(components.hash_start);
  components.hash_start = uint32_t(buffer.size());
  buffer += "#";
  unicode::percent_encode<true>(input,ada::character_sets::FRAGMENT_PERCENT_ENCODE, buffer);
}

inline void url_aggregator::update_base_search(std::string_view input) {
  bool has_hash = components.hash_start != url_components::omitted;
  if (has_hash) {
    // TODO: Implement this.
  } else {
    buffer.resize(components.search_start);
    buffer += "?";
    buffer += input;
  }
}

inline void url_aggregator::update_base_search(std::string_view input, const uint8_t query_percent_encode_set[]) {
  bool has_hash = components.hash_start != url_components::omitted;
  if (has_hash) {
    // TODO: Implement this.
  } else {
    buffer.resize(components.search_start);
    buffer += "?";
    unicode::percent_encode<true>(input, query_percent_encode_set, buffer);
  }
}

inline void url_aggregator::update_base_search(std::optional<std::string_view> input) {
  bool has_hash = components.hash_start != url_components::omitted;

  if (has_hash) {
    // TODO: Implement this.
  } else {
    buffer.resize(components.search_start);

    if (input.has_value()) {
      buffer += "?";
      buffer += input.value();
    } else {
      components.search_start = url_components::omitted;
    }
  }
}

inline void url_aggregator::update_base_pathname(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
}

inline void url_aggregator::update_base_username(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
}

inline void url_aggregator::update_base_password(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
}

inline void url_aggregator::update_base_port(std::optional<uint16_t> input) {
  components.port = input.value_or(url_components::omitted);
}

inline std::optional<uint16_t> url_aggregator::retrieve_base_port() const {
  if (components.port == url_components::omitted) {
    return std::nullopt;
  }
  return components.port;
}

inline std::string_view url_aggregator::retrieve_base_pathname() const {
  size_t ending = buffer.size();
  if (base_search_has_value()) { ending = components.search_start; }
  else if (base_fragment_has_value()) { ending = components.hash_start; }
  return helpers::substring(buffer, components.pathname_start, ending);
}

inline void url_aggregator::clear_base_hash() {
  components.hash_start = url_components::omitted;
  buffer.resize(components.hash_start);
}

inline bool url_aggregator::base_fragment_has_value() const {
  return components.hash_start != url_components::omitted;
}

inline bool url_aggregator::base_search_has_value() const {
  return components.search_start != url_components::omitted;
}

inline bool url_aggregator::base_port_has_value() const {
  return components.port != url_components::omitted;
}

inline bool url_aggregator::base_hostname_has_value() const {
  return components.host_start != components.host_end;
}

ada_really_inline bool url_aggregator::includes_credentials() const noexcept {
  if (components.username_end > components.protocol_end + 3) { return true; }
  if (buffer[components.username_end] == ':' && components.username_end + 1 < components.host_start) { return true; }
  return false;
}

inline bool url_aggregator::cannot_have_credentials_or_port() const {
  return type == ada::scheme::type::FILE || components.host_start == components.host_end;
}

[[nodiscard]] ada_really_inline const ada::url_components& url_aggregator::get_components() const noexcept {
  return components;
}

inline bool ada::url_aggregator::has_authority() const noexcept {
  return (components.protocol_end + 3 <= buffer.size()) && helpers::substring(buffer, components.protocol_end, components.protocol_end + 3) == "://";
}

}

#endif // ADA_URL_AGGREGATOR_INL_H