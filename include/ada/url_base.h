/**
 * @file url_base.h
 * @brief Declaration for the basic URL definitions
 */
#ifndef ADA_URL_BASE_H
#define ADA_URL_BASE_H

#include "ada/common_defs.h"
#include "ada/url_components.h"
#include "ada/scheme.h"

#include <string_view>

namespace ada {

/**
 * Type of URL host as an enum.
 */
enum url_host_type : uint8_t {
  /**
   * Represents common URLs such as "https://www.google.com"
   */
  DEFAULT = 0,
  /**
   * Represents ipv4 addresses such as "http://127.0.0.1"
   */
  IPV4 = 1,
  /**
   * Represents ipv6 addresses such as
   * "http://[2001:db8:3333:4444:5555:6666:7777:8888]"
   */
  IPV6 = 2,
};

/**
 * @brief Base class of URL implementations
 *
 * @details A url_base contains a few attributes: is_valid, has_opaque_path and
 * type. All non-trivial implementation details are in derived classes such as
 * ada::url and ada::url_aggregator.
 *
 * It is an abstract class that cannot be instantiated directly.
 */
struct url_base {
  virtual ~url_base() = default;

  /**
   * Used for returning the validity from the result of the URL parser.
   */
  bool is_valid{true};

  /**
   * A URL has an opaque path if its path is a string.
   */
  bool has_opaque_path{false};

  /**
   * URL hosts type
   */
  url_host_type host_type = url_host_type::DEFAULT;

  /**
   * @private
   */
  ada::scheme::type type{ada::scheme::type::NOT_SPECIAL};

  /**
   * A URL is special if its scheme is a special scheme. A URL is not special if
   * its scheme is not a special scheme.
   */
  [[nodiscard]] ada_really_inline bool is_special() const noexcept;

  /**
   * The origin getter steps are to return the serialization of this's URL's
   * origin. [HTML]
   * @return a newly allocated string.
   * @see https://url.spec.whatwg.org/#concept-url-origin
   */
  [[nodiscard]] virtual std::string get_origin() const noexcept = 0;

  /**
   * Returns true if this URL has a valid domain as per RFC 1034 and
   * corresponding specifications. Among other things, it requires
   * that the domain string has fewer than 255 octets.
   */
  [[nodiscard]] virtual bool has_valid_domain() const noexcept = 0;

  /**
   * @private
   *
   * Return the 'special port' if the URL is special and not 'file'.
   * Returns 0 otherwise.
   */
  [[nodiscard]] inline uint16_t get_special_port() const noexcept;

  /**
   * @private
   *
   * Get the default port if the url's scheme has one, returns 0 otherwise.
   */
  [[nodiscard]] ada_really_inline uint16_t scheme_default_port() const noexcept;

  /**
   * @private
   *
   * Parse a port (16-bit decimal digit) from the provided input.
   * We assume that the input does not contain spaces or tabs
   * within the ASCII digits.
   * It returns how many bytes were consumed when a number is successfully
   * parsed.
   * @return On failure, it returns zero.
   * @see https://url.spec.whatwg.org/#host-parsing
   */
  virtual size_t parse_port(std::string_view view,
                            bool check_trailing_content) noexcept = 0;

  virtual ada_really_inline size_t parse_port(std::string_view view) noexcept {
    return this->parse_port(view, false);
  }

  /**
   * Returns a JSON string representation of this URL.
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
