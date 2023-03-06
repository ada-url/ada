/**
 * @file url_aggregator-inl.h
 * @brief Inline functions for url aggregator
 */
#ifndef ADA_URL_AGGREGATOR_INL_H
#define ADA_URL_AGGREGATOR_INL_H

#include "ada/url_aggregator.h"
#include "ada/url_components.h"
#include "ada/scheme.h"

namespace ada {

void url_aggregator::update_base_hash(std::optional<std::string> input) {
  if (components.hash_start != url_components::omitted) {
    buffer.resize(components.hash_start);
  }

  if (!input.has_value()) {
    components.hash_start = url_components::omitted;
    return;
  }

  components.hash_start = uint32_t(buffer.size());
  buffer += "#";
  buffer.append(input.value());
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

}

#endif // ADA_URL_AGGREGATOR_INL_H