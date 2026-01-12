/**
 * @file url_base.h
 * @brief Base class and common definitions for URL types.
 *
 * This file defines the `url_base` abstract base class from which both
 * `ada::url` and `ada::url_aggregator` inherit. It also defines common
 * enumerations like `url_host_type`.
 */
#ifndef ADA_URL_BASE_H
#define ADA_URL_BASE_H

#include "ada/common_defs.h"
#include "ada/scheme.h"

#include <string>
#include <string_view>

namespace ada {

/**
 * @brief Enum representing the type of host in a URL.
 *
 * Used to distinguish between regular domain names, IPv4 addresses,
 * and IPv6 addresses for proper parsing and serialization.
 */
enum url_host_type : uint8_t {
  /** Regular domain name (e.g., "www.example.com") */
  DEFAULT = 0,
  /** IPv4 address (e.g., "127.0.0.1") */
  IPV4 = 1,
  /** IPv6 address (e.g., "[::1]" or "[2001:db8::1]") */
  IPV6 = 2,
};

/**
 * @brief Abstract base class for URL representations.
 *
 * The `url_base` class provides the common interface and state shared by
 * both `ada::url` and `ada::url_aggregator`. It contains basic URL attributes
 * like validity status and scheme type, but delegates component storage and
 * access to derived classes.
 *
 * @note This is an abstract class and cannot be instantiated directly.
 *       Use `ada::url` or `ada::url_aggregator` instead.
 *
 * @see url
 * @see url_aggregator
 */
struct url_base {
  virtual ~url_base() = default;

  /**
   * Indicates whether the URL was successfully parsed.
   * Set to `false` if parsing failed (e.g., invalid URL syntax).
   */
  bool is_valid{true};

  /**
   * Indicates whether the URL has an opaque path (non-hierarchical).
   * Opaque paths occur in non-special URLs like `mailto:` or `javascript:`.
   */
  bool has_opaque_path{false};

  /**
   * The type of the URL's host (domain, IPv4, or IPv6).
   */
  url_host_type host_type = url_host_type::DEFAULT;

  /**
   * @private
   * Internal representation of the URL's scheme type.
   */
  ada::scheme::type type{ada::scheme::type::NOT_SPECIAL};

  /**
   * Checks if the URL has a special scheme (http, https, ws, wss, ftp, file).
   * Special schemes have specific parsing rules and default ports.
   * @return `true` if the scheme is special, `false` otherwise.
   */
  [[nodiscard]] ada_really_inline constexpr bool is_special() const noexcept;

  /**
   * Returns the URL's origin (scheme + host + port for special URLs).
   * @return A newly allocated string containing the serialized origin.
   * @see https://url.spec.whatwg.org/#concept-url-origin
   */
  [[nodiscard]] virtual std::string get_origin() const = 0;

  /**
   * Validates whether the hostname is a valid domain according to RFC 1034.
   * Checks that the domain and its labels have valid lengths.
   * @return `true` if the domain is valid, `false` otherwise.
   */
  [[nodiscard]] virtual bool has_valid_domain() const noexcept = 0;

  /**
   * @private
   * Returns the default port for special schemes (e.g., 443 for https).
   * Returns 0 for file:// URLs or non-special schemes.
   */
  [[nodiscard]] inline uint16_t get_special_port() const noexcept;

  /**
   * @private
   * Returns the default port for the URL's scheme, or 0 if none.
   */
  [[nodiscard]] ada_really_inline uint16_t scheme_default_port() const noexcept;

  /**
   * @private
   * Parses a port number from the input string.
   * @param view The string containing the port to parse.
   * @param check_trailing_content Whether to validate no trailing characters.
   * @return Number of bytes consumed on success, 0 on failure.
   */
  virtual size_t parse_port(std::string_view view,
                            bool check_trailing_content) = 0;

  /** @private */
  virtual ada_really_inline size_t parse_port(std::string_view view) {
    return this->parse_port(view, false);
  }

  /**
   * Returns a JSON string representation of this URL for debugging.
   * @return A JSON-formatted string with URL information.
   */
  [[nodiscard]] virtual std::string to_string() const = 0;

  /** @private */
  virtual inline void clear_pathname() = 0;

  /** @private */
  virtual inline void clear_search() = 0;

  /** @private */
  [[nodiscard]] virtual inline bool has_hash() const noexcept = 0;

  /** @private */
  [[nodiscard]] virtual inline bool has_search() const noexcept = 0;

};  // url_base

}  // namespace ada

#endif
