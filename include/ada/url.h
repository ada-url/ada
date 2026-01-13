/**
 * @file url.h
 * @brief Declaration for the `ada::url` class.
 *
 * This file contains the `ada::url` struct which represents a parsed URL
 * using separate `std::string` instances for each component. This
 * representation is more flexible but uses more memory than `url_aggregator`.
 *
 * @see url_aggregator.h for a more memory-efficient alternative
 */
#ifndef ADA_URL_H
#define ADA_URL_H

#include <algorithm>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>

#include "ada/checkers.h"
#include "ada/common_defs.h"
#include "ada/url_base.h"
#include "ada/url_components.h"
#include "ada/helpers.h"

namespace ada {

struct url_aggregator;

// namespace parser {
// template <typename result_type>
// result_type parse_url(std::string_view user_input,
//                       const result_type* base_url = nullptr);
// template <typename result_type, bool store_values>
// result_type parse_url_impl(std::string_view user_input,
//                            const result_type* base_url = nullptr);
// }

/**
 * @brief Represents a parsed URL with individual string components.
 *
 * The `url` struct stores each URL component (scheme, username, password,
 * host, port, path, query, fragment) as a separate `std::string`. This
 * provides flexibility but incurs more memory allocations compared to
 * `url_aggregator`.
 *
 * **When to use `ada::url`:**
 * - When you need to frequently modify individual URL components
 * - When you want independent ownership of component strings
 *
 * **When to use `ada::url_aggregator` instead:**
 * - For read-mostly operations on parsed URLs
 * - When memory efficiency is important
 * - When you only need string_view access to components
 *
 * @note This type is returned when parsing with `ada::parse<ada::url>()`.
 *       By default, `ada::parse()` returns `ada::url_aggregator`.
 *
 * @see url_aggregator For a more memory-efficient URL representation
 * @see https://url.spec.whatwg.org/#url-representation
 */
struct url : url_base {
  url() = default;
  url(const url &u) = default;
  url(url &&u) noexcept = default;
  url &operator=(url &&u) noexcept = default;
  url &operator=(const url &u) = default;
  ~url() override = default;

  /**
   * @private
   * A URL's username is an ASCII string identifying a username. It is initially
   * the empty string.
   */
  std::string username{};

  /**
   * @private
   * A URL's password is an ASCII string identifying a password. It is initially
   * the empty string.
   */
  std::string password{};

  /**
   * @private
   * A URL's host is null or a host. It is initially null.
   */
  std::optional<std::string> host{};

  /**
   * @private
   * A URL's port is either null or a 16-bit unsigned integer that identifies a
   * networking port. It is initially null.
   */
  std::optional<uint16_t> port{};

  /**
   * @private
   * A URL's path is either an ASCII string or a list of zero or more ASCII
   * strings, usually identifying a location.
   */
  std::string path{};

  /**
   * @private
   * A URL's query is either null or an ASCII string. It is initially null.
   */
  std::optional<std::string> query{};

  /**
   * @private
   * A URL's fragment is either null or an ASCII string that can be used for
   * further processing on the resource the URL's other components identify. It
   * is initially null.
   */
  std::optional<std::string> hash{};

  /**
   * Checks if the URL has an empty hostname (host is set but empty string).
   * @return `true` if host exists but is empty, `false` otherwise.
   */
  [[nodiscard]] inline bool has_empty_hostname() const noexcept;

  /**
   * Checks if the URL has a non-default port explicitly specified.
   * @return `true` if a port is present, `false` otherwise.
   */
  [[nodiscard]] inline bool has_port() const noexcept;

  /**
   * Checks if the URL has a hostname (including empty hostnames).
   * @return `true` if host is present, `false` otherwise.
   */
  [[nodiscard]] inline bool has_hostname() const noexcept;

  /**
   * Validates whether the hostname is a valid domain according to RFC 1034.
   * Checks that the domain and its labels have valid lengths (max 255 octets
   * total, max 63 octets per label).
   * @return `true` if the domain is valid, `false` otherwise.
   */
  [[nodiscard]] bool has_valid_domain() const noexcept override;

  /**
   * Returns a JSON string representation of this URL for debugging.
   * @return A JSON-formatted string with all URL components.
   */
  [[nodiscard]] std::string to_string() const override;

  /**
   * Returns the full serialized URL (the href).
   * @return The complete URL string (allocates a new string).
   * @see https://url.spec.whatwg.org/#dom-url-href
   */
  [[nodiscard]] ada_really_inline std::string get_href() const;

  /**
   * Returns the URL's origin as a string (scheme + host + port for special
   * URLs).
   * @return A newly allocated string containing the serialized origin.
   * @see https://url.spec.whatwg.org/#concept-url-origin
   */
  [[nodiscard]] std::string get_origin() const override;

  /**
   * Returns the URL's scheme followed by a colon (e.g., "https:").
   * @return A newly allocated string with the protocol.
   * @see https://url.spec.whatwg.org/#dom-url-protocol
   */
  [[nodiscard]] std::string get_protocol() const;

  /**
   * Returns the URL's host and port (e.g., "example.com:8080").
   * If no port is set, returns just the host. Returns empty string if no host.
   * @return A newly allocated string with host:port.
   * @see https://url.spec.whatwg.org/#dom-url-host
   */
  [[nodiscard]] std::string get_host() const;

  /**
   * Returns the URL's hostname (without port).
   * Returns empty string if no host is set.
   * @return A newly allocated string with the hostname.
   * @see https://url.spec.whatwg.org/#dom-url-hostname
   */
  [[nodiscard]] std::string get_hostname() const;

  /**
   * Returns the URL's path component.
   * @return A string_view pointing to the path.
   * @see https://url.spec.whatwg.org/#dom-url-pathname
   */
  [[nodiscard]] constexpr std::string_view get_pathname() const noexcept;

  /**
   * Returns the byte length of the pathname without creating a string.
   * @return Size of the pathname in bytes.
   * @see https://url.spec.whatwg.org/#dom-url-pathname
   */
  [[nodiscard]] ada_really_inline size_t get_pathname_length() const noexcept;

  /**
   * Returns the URL's query string prefixed with '?' (e.g., "?foo=bar").
   * Returns empty string if no query is set.
   * @return A newly allocated string with the search/query.
   * @see https://url.spec.whatwg.org/#dom-url-search
   */
  [[nodiscard]] std::string get_search() const;

  /**
   * Returns the URL's username component.
   * @return A constant reference to the username string.
   * @see https://url.spec.whatwg.org/#dom-url-username
   */
  [[nodiscard]] const std::string &get_username() const noexcept;

  /**
   * Sets the URL's username, percent-encoding special characters.
   * @param input The new username value.
   * @return `true` on success, `false` if the URL cannot have credentials.
   * @see https://url.spec.whatwg.org/#dom-url-username
   */
  bool set_username(std::string_view input);

  /**
   * Sets the URL's password, percent-encoding special characters.
   * @param input The new password value.
   * @return `true` on success, `false` if the URL cannot have credentials.
   * @see https://url.spec.whatwg.org/#dom-url-password
   */
  bool set_password(std::string_view input);

  /**
   * Sets the URL's port from a string (e.g., "8080").
   * @param input The port string. Empty string removes the port.
   * @return `true` on success, `false` if the URL cannot have a port.
   * @see https://url.spec.whatwg.org/#dom-url-port
   */
  bool set_port(std::string_view input);

  /**
   * Sets the URL's fragment/hash (the part after '#').
   * @param input The new hash value (with or without leading '#').
   * @see https://url.spec.whatwg.org/#dom-url-hash
   */
  void set_hash(std::string_view input);

  /**
   * Sets the URL's query string (the part after '?').
   * @param input The new query value (with or without leading '?').
   * @see https://url.spec.whatwg.org/#dom-url-search
   */
  void set_search(std::string_view input);

  /**
   * Sets the URL's pathname.
   * @param input The new path value.
   * @return `true` on success, `false` if the URL has an opaque path.
   * @see https://url.spec.whatwg.org/#dom-url-pathname
   */
  bool set_pathname(std::string_view input);

  /**
   * Sets the URL's host (hostname and optionally port).
   * @param input The new host value (e.g., "example.com:8080").
   * @return `true` on success, `false` if parsing fails.
   * @see https://url.spec.whatwg.org/#dom-url-host
   */
  bool set_host(std::string_view input);

  /**
   * Sets the URL's hostname (without port).
   * @param input The new hostname value.
   * @return `true` on success, `false` if parsing fails.
   * @see https://url.spec.whatwg.org/#dom-url-hostname
   */
  bool set_hostname(std::string_view input);

  /**
   * Sets the URL's protocol/scheme.
   * @param input The new protocol (with or without trailing ':').
   * @return `true` on success, `false` if the scheme is invalid.
   * @see https://url.spec.whatwg.org/#dom-url-protocol
   */
  bool set_protocol(std::string_view input);

  /**
   * Replaces the entire URL by parsing a new href string.
   * @param input The new URL string to parse.
   * @return `true` on success, `false` if parsing fails.
   * @see https://url.spec.whatwg.org/#dom-url-href
   */
  bool set_href(std::string_view input);

  /**
   * Returns the URL's password component.
   * @return A constant reference to the password string.
   * @see https://url.spec.whatwg.org/#dom-url-password
   */
  [[nodiscard]] const std::string &get_password() const noexcept;

  /**
   * Returns the URL's port as a string (e.g., "8080").
   * Returns empty string if no port is set.
   * @return A newly allocated string with the port.
   * @see https://url.spec.whatwg.org/#dom-url-port
   */
  [[nodiscard]] std::string get_port() const;

  /**
   * Returns the URL's fragment prefixed with '#' (e.g., "#section").
   * Returns empty string if no fragment is set.
   * @return A newly allocated string with the hash.
   * @see https://url.spec.whatwg.org/#dom-url-hash
   */
  [[nodiscard]] std::string get_hash() const;

  /**
   * Checks if the URL has credentials (non-empty username or password).
   * @return `true` if username or password is non-empty, `false` otherwise.
   */
  [[nodiscard]] ada_really_inline bool has_credentials() const noexcept;

  /**
   * Returns the URL component offsets for efficient serialization.
   *
   * The components represent byte offsets into the serialized URL:
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
   * @return A newly constructed url_components struct.
   * @see https://github.com/servo/rust-url
   */
  [[nodiscard]] ada_really_inline ada::url_components get_components()
      const noexcept;

  /**
   * Checks if the URL has a fragment/hash component.
   * @return `true` if hash is present, `false` otherwise.
   */
  [[nodiscard]] constexpr bool has_hash() const noexcept override;

  /**
   * Checks if the URL has a query/search component.
   * @return `true` if query is present, `false` otherwise.
   */
  [[nodiscard]] constexpr bool has_search() const noexcept override;

 private:
  friend ada::url ada::parser::parse_url<ada::url>(std::string_view,
                                                   const ada::url *);
  friend ada::url_aggregator ada::parser::parse_url<ada::url_aggregator>(
      std::string_view, const ada::url_aggregator *);
  friend void ada::helpers::strip_trailing_spaces_from_opaque_path<ada::url>(
      ada::url &url);

  friend ada::url ada::parser::parse_url_impl<ada::url, true>(std::string_view,
                                                              const ada::url *);
  friend ada::url_aggregator ada::parser::parse_url_impl<
      ada::url_aggregator, true>(std::string_view, const ada::url_aggregator *);

  inline void update_unencoded_base_hash(std::string_view input);
  inline void update_base_hostname(std::string_view input);
  inline void update_base_search(std::string_view input,
                                 const uint8_t query_percent_encode_set[]);
  inline void update_base_search(std::optional<std::string> &&input);
  inline void update_base_pathname(std::string_view input);
  inline void update_base_username(std::string_view input);
  inline void update_base_password(std::string_view input);
  inline void update_base_port(std::optional<uint16_t> input);

  /**
   * Sets the host or hostname according to override condition.
   * Return true on success.
   * @see https://url.spec.whatwg.org/#hostname-state
   */
  template <bool override_hostname = false>
  bool set_host_or_hostname(std::string_view input);

  /**
   * Return true on success.
   * @see https://url.spec.whatwg.org/#concept-ipv4-parser
   */
  [[nodiscard]] bool parse_ipv4(std::string_view input);

  /**
   * Return true on success.
   * @see https://url.spec.whatwg.org/#concept-ipv6-parser
   */
  [[nodiscard]] bool parse_ipv6(std::string_view input);

  /**
   * Return true on success.
   * @see https://url.spec.whatwg.org/#concept-opaque-host-parser
   */
  [[nodiscard]] bool parse_opaque_host(std::string_view input);

  /**
   * A URL's scheme is an ASCII string that identifies the type of URL and can
   * be used to dispatch a URL for further processing after parsing. It is
   * initially the empty string. We only set non_special_scheme when the scheme
   * is non-special, otherwise we avoid constructing string.
   *
   * Special schemes are stored in ada::scheme::details::is_special_list so we
   * typically do not need to store them in each url instance.
   */
  std::string non_special_scheme{};

  /**
   * A URL cannot have a username/password/port if its host is null or the empty
   * string, or its scheme is "file".
   */
  [[nodiscard]] inline bool cannot_have_credentials_or_port() const;

  ada_really_inline size_t parse_port(
      std::string_view view, bool check_trailing_content) noexcept override;

  ada_really_inline size_t parse_port(std::string_view view) noexcept override {
    return this->parse_port(view, false);
  }

  /**
   * Parse the host from the provided input. We assume that
   * the input does not contain spaces or tabs. Control
   * characters and spaces are not trimmed (they should have
   * been removed if needed).
   * Return true on success.
   * @see https://url.spec.whatwg.org/#host-parsing
   */
  [[nodiscard]] ada_really_inline bool parse_host(std::string_view input);

  template <bool has_state_override = false>
  [[nodiscard]] ada_really_inline bool parse_scheme(std::string_view input);

  constexpr void clear_pathname() override;
  constexpr void clear_search() override;
  constexpr void set_protocol_as_file();

  /**
   * Parse the path from the provided input.
   * Return true on success. Control characters not
   * trimmed from the ends (they should have
   * been removed if needed).
   *
   * The input is expected to be UTF-8.
   *
   * @see https://url.spec.whatwg.org/
   */
  ada_really_inline void parse_path(std::string_view input);

  /**
   * Set the scheme for this URL. The provided scheme should be a valid
   * scheme string, be lower-cased, not contain spaces or tabs. It should
   * have no spurious trailing or leading content.
   */
  inline void set_scheme(std::string &&new_scheme) noexcept;

  /**
   * Take the scheme from another URL. The scheme string is moved from the
   * provided url.
   */
  constexpr void copy_scheme(ada::url &&u);

  /**
   * Take the scheme from another URL. The scheme string is copied from the
   * provided url.
   */
  constexpr void copy_scheme(const ada::url &u);

};  // struct url

inline std::ostream &operator<<(std::ostream &out, const ada::url &u);
}  // namespace ada

#endif  // ADA_URL_H
