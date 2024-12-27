/**
 * @file url_components.h
 * @brief Declaration for the URL Components
 */
#ifndef ADA_URL_COMPONENTS_INL_H
#define ADA_URL_COMPONENTS_INL_H

#include "helpers.h"
#include "url_components.h"

namespace ada {

[[nodiscard]] constexpr bool url_components::check_offset_consistency()
    const noexcept {
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
  // These conditions can be made more strict.
  uint32_t index = 0;

  if (protocol_end == url_components::omitted) {
    return false;
  }
  if (protocol_end < index) {
    return false;
  }
  index = protocol_end;

  if (username_end == url_components::omitted) {
    return false;
  }
  if (username_end < index) {
    return false;
  }
  index = username_end;

  if (host_start == url_components::omitted) {
    return false;
  }
  if (host_start < index) {
    return false;
  }
  index = host_start;

  if (port != url_components::omitted) {
    if (port > 0xffff) {
      return false;
    }
    uint32_t port_length = helpers::fast_digit_count(port) + 1;
    if (index + port_length < index) {
      return false;
    }
    index += port_length;
  }

  if (pathname_start == url_components::omitted) {
    return false;
  }
  if (pathname_start < index) {
    return false;
  }
  index = pathname_start;

  if (search_start != url_components::omitted) {
    if (search_start < index) {
      return false;
    }
    index = search_start;
  }

  if (hash_start != url_components::omitted) {
    if (hash_start < index) {
      return false;
    }
  }

  return true;
}

}  // namespace ada
#endif
