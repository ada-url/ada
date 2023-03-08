/**
 * @file url_aggregator-inl.h
 * @brief Inline functions for url aggregator
 */
#ifndef ADA_URL_AGGREGATOR_INL_H
#define ADA_URL_AGGREGATOR_INL_H

#include "ada/url_aggregator.h"
#include "ada/url_components.h"
#include "ada/scheme.h"

#include <optional>

namespace ada {

void url_aggregator::update_base_hash(std::string_view input) {
  buffer.resize(components.hash_start);
  components.hash_start = uint32_t(buffer.size());
  buffer += "#";
  buffer.append(input);
}

void url_aggregator::update_base_search(std::optional<std::string> input) {
  bool has_hash = components.hash_start != url_components::omitted;

  if (has_hash) {
    // TODO: Implement this.
  } else {
    buffer.resize(components.search_start);

    if (input.has_value()) {
      buffer += "?";
      buffer.append(input.value());
    } else {
      components.search_start = url_components::omitted;
    }
  }
}

void url_aggregator::update_base_pathname(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
}

void url_aggregator::update_base_username(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
}

void url_aggregator::update_base_password(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
}

void url_aggregator::update_base_port(std::optional<uint32_t> input) {
  components.port = input.value_or(url_components::omitted);
}

std::optional<uint32_t> url_aggregator::retrieve_base_port() {
  if (components.port == url_components::omitted) {
    return std::nullopt;
  }
  return components.port;
}

void url_aggregator::clear_base_hash() {
  components.hash_start = url_components::omitted;
  buffer.resize(components.hash_start);
}

bool url_aggregator::base_fragment_has_value() const {
  return components.hash_start != url_components::omitted;
}

bool url_aggregator::base_search_has_value() const {
  return components.search_start != url_components::omitted;
}

bool url_aggregator::base_port_has_value() const {
  return components.port != url_components::omitted;
}

bool url_aggregator::base_hostname_has_value() const {
  return components.host_start != components.host_end;
}

ada_really_inline bool url_aggregator::includes_credentials() const noexcept {
  // TODO: Implement this
  return false;
}

inline bool url_aggregator::cannot_have_credentials_or_port() const {
  // TODO: Implement this
  return false;
}

}

#endif // ADA_URL_AGGREGATOR_INL_H