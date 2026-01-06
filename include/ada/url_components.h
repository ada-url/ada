/**
 * @file url_components.h
 * @brief URL component offset representation for url_aggregator.
 *
 * This file defines the `url_components` struct which stores byte offsets
 * into a URL string buffer. It is used internally by `url_aggregator` to
 * efficiently locate URL components without storing separate strings.
 */
#ifndef ADA_URL_COMPONENTS_H
#define ADA_URL_COMPONENTS_H

namespace ada {

/**
 * @brief Stores byte offsets for URL components within a buffer.
 *
 * The `url_components` struct uses 32-bit offsets to track the boundaries
 * of each URL component within a single string buffer. This enables efficient
 * component extraction without additional memory allocations.
 *
 * Component layout in a URL:
 * ```
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
 * ```
 *
 * @note The 32-bit offsets limit URLs to 4GB in length.
 * @note A value of `omitted` (UINT32_MAX) indicates the component is not
 * present.
 */
struct url_components {
  /** Sentinel value indicating a component is not present. */
  constexpr static uint32_t omitted = uint32_t(-1);

  url_components() = default;
  url_components(const url_components &u) = default;
  url_components(url_components &&u) noexcept = default;
  url_components &operator=(url_components &&u) noexcept = default;
  url_components &operator=(const url_components &u) = default;
  ~url_components() = default;

  /** Offset of the end of the protocol/scheme (position of ':'). */
  uint32_t protocol_end{0};

  /**
   * Offset of the end of the username.
   * Initialized to 0 (not `omitted`) to simplify username/password getters.
   */
  uint32_t username_end{0};

  /** Offset of the start of the host. */
  uint32_t host_start{0};

  /** Offset of the end of the host. */
  uint32_t host_end{0};

  /** Port number, or `omitted` if no port is specified. */
  uint32_t port{omitted};

  /** Offset of the start of the pathname. */
  uint32_t pathname_start{0};

  /** Offset of the '?' starting the query, or `omitted` if no query. */
  uint32_t search_start{omitted};

  /** Offset of the '#' starting the fragment, or `omitted` if no fragment. */
  uint32_t hash_start{omitted};

  /**
   * Validates that offsets are in ascending order and consistent.
   * Useful for debugging to detect internal corruption.
   * @return `true` if offsets are consistent, `false` otherwise.
   */
  [[nodiscard]] constexpr bool check_offset_consistency() const noexcept;

  /**
   * Returns a JSON string representation of the offsets for debugging.
   * @return A JSON-formatted string with all offset values.
   */
  [[nodiscard]] std::string to_string() const;

};  // struct url_components
}  // namespace ada
#endif
