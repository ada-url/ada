/**
 * @file scheme.h
 * @brief URL scheme type definitions and utilities.
 *
 * This header defines the URL scheme types (http, https, etc.) and provides
 * functions to identify special schemes and their default ports according
 * to the WHATWG URL Standard.
 *
 * @see https://url.spec.whatwg.org/#special-scheme
 */
#ifndef ADA_SCHEME_H
#define ADA_SCHEME_H

#include "ada/common_defs.h"

#include <string>

/**
 * @namespace ada::scheme
 * @brief URL scheme utilities and constants.
 *
 * Provides functions for working with URL schemes, including identification
 * of special schemes and retrieval of default port numbers.
 */
namespace ada::scheme {

/**
 * @brief Enumeration of URL scheme types.
 *
 * Special schemes have specific parsing rules and default ports.
 * Using an enum allows efficient scheme comparisons without string operations.
 *
 * Default ports:
 * - HTTP: 80
 * - HTTPS: 443
 * - WS: 80
 * - WSS: 443
 * - FTP: 21
 * - FILE: (none)
 */
enum type : uint8_t {
  HTTP = 0,        /**< http:// scheme (port 80) */
  NOT_SPECIAL = 1, /**< Non-special scheme (no default port) */
  HTTPS = 2,       /**< https:// scheme (port 443) */
  WS = 3,          /**< ws:// WebSocket scheme (port 80) */
  FTP = 4,         /**< ftp:// scheme (port 21) */
  WSS = 5,         /**< wss:// secure WebSocket scheme (port 443) */
  FILE = 6         /**< file:// scheme (no default port) */
};

/**
 * Checks if a scheme string is a special scheme.
 * @param scheme The scheme string to check (e.g., "http", "https").
 * @return `true` if the scheme is special, `false` otherwise.
 * @see https://url.spec.whatwg.org/#special-scheme
 */
ada_really_inline constexpr bool is_special(std::string_view scheme);

/**
 * Returns the default port for a special scheme string.
 * @param scheme The scheme string (e.g., "http", "https").
 * @return The default port number, or 0 if not a special scheme.
 * @see https://url.spec.whatwg.org/#special-scheme
 */
constexpr uint16_t get_special_port(std::string_view scheme) noexcept;

/**
 * Returns the default port for a scheme type.
 * @param type The scheme type enum value.
 * @return The default port number, or 0 if not applicable.
 * @see https://url.spec.whatwg.org/#special-scheme
 */
constexpr uint16_t get_special_port(ada::scheme::type type) noexcept;

/**
 * Converts a scheme string to its type enum.
 * @param scheme The scheme string to convert.
 * @return The corresponding scheme type, or NOT_SPECIAL if not recognized.
 */
constexpr ada::scheme::type get_scheme_type(std::string_view scheme) noexcept;

}  // namespace ada::scheme

#endif  // ADA_SCHEME_H
