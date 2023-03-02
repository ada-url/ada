/**
 * @file url-components.h
 * @brief Declaration for the URL Components
 */
#ifndef ADA_URL_COMPONENTS_H
#define ADA_URL_COMPONENTS_H

#include "ada/common_defs.h"

#include <optional>
#include <string_view>

namespace ada {

  /**
   * We design the url_components struct so that it is as small
   * and simple as possible. This version uses 32 bytes. A version with size_t
   * and std::optional<size_t> might use 80 bytes or more.
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
     */
    uint32_t protocol_end{0};
    uint32_t username_end{0};
    uint32_t host_start{0};
    uint32_t host_end{0};
    uint32_t port{omitted};
    uint32_t pathname_start{0};
    uint32_t search_start{omitted};
    uint32_t hash_start{omitted};
     /**
      *
      * https://user@pass:example.com:1234/foo/bar?baz#quux
      *      |      |    |          | ^^^^|       |   |
      *      |      |    |          | |   |       |   `----- hash_start
      *      |      |    |          | |   |       `--------- search_start
      *      |      |    |          | |   `----------------- pathname_start
      *      |      |    |          | `--------------------- port
      *      |      |    |          `----------------------- host_end
      *      |      |    `---------------------------------- host_start
      *      |      `--------------------------------------- username_end
      *      `---------------------------------------------- protocol_end
      */


    std::string to_string() const;

  }; // struct url_components

} // namespace ada
#endif