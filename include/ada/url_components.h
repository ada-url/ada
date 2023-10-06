/**
 * @file url_components.h
 * @brief Declaration for the URL Components
 */
#ifndef ADA_URL_COMPONENTS_H
#define ADA_URL_COMPONENTS_H

#include "ada/common_defs.h"

#include <optional>
#include <string_view>

namespace ada {

/**
 * @brief URL Component representations using offsets.
 *
 * @details We design the url_components struct so that it is as small
 * and simple as possible. This version uses 32 bytes.
 *
 * This struct is used to extract components from a single 'href'.
 */
struct url_components {
  constexpr static uint32_t omitted = uint32_t(-1);

  url_components() = default;
  url_components(const url_components &u) = default;
  url_components(url_components &&u) noexcept = default;
  url_components &operator=(url_components &&u) noexcept = default;
  url_components &operator=(const url_components &u) = default;
  ~url_components() = default;

  /*
   * By using 32-bit integers, we implicitly assume that the URL string
   * cannot exceed 4 GB.
   *
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
  uint32_t protocol_end{0};
  /**
   * Username end is not `omitted` by default to make username and password
   * getters less costly to implement.
   */
  uint32_t username_end{0};
  uint32_t host_start{0};
  uint32_t host_end{0};
  uint32_t port{omitted};
  uint32_t pathname_start{0};
  uint32_t search_start{omitted};
  uint32_t hash_start{omitted};

  /**
   * Check the following conditions:
   * protocol_end < username_end < ... < hash_start,
   * expect when a value is omitted. It also computes
   * a lower bound on  the possible string length that may match these
   * offsets.
   * @return true if the offset values are
   *  consistent with a possible URL string
   */
  [[nodiscard]] bool check_offset_consistency() const noexcept;

  /**
   * Converts a url_components to JSON stringified version.
   */
  [[nodiscard]] std::string to_string() const;

};  // struct url_components

}  // namespace ada
#endif
