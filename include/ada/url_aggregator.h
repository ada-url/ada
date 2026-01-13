/**
 * @file url_aggregator.h
 * @brief Declaration for the `ada::url_aggregator` class.
 *
 * This file contains the `ada::url_aggregator` struct which represents a parsed
 * URL using a single buffer with component offsets. This is the default and
 * most memory-efficient URL representation in Ada.
 *
 * @see url.h for an alternative representation using separate strings
 */
#ifndef ADA_URL_AGGREGATOR_H
#define ADA_URL_AGGREGATOR_H

#include <ostream>
#include <string>
#include <string_view>
#include <variant>

#include "ada/common_defs.h"
#include "ada/url_base.h"
#include "ada/url_components.h"

namespace ada {

namespace parser {}

/**
 * @brief Memory-efficient URL representation using a single buffer.
 *
 * The `url_aggregator` stores the entire normalized URL in a single string
 * buffer and tracks component boundaries using offsets. This design minimizes
 * memory allocations and is ideal for read-mostly access patterns.
 *
 * Getter methods return `std::string_view` pointing into the internal buffer.
 * These views are lightweight (no allocation) but become invalid if the
 * url_aggregator is modified or destroyed.
 *
 * @warning Views returned by getters (e.g., `get_pathname()`) are invalidated
 * when any setter is called. Do not use a getter's result as input to a
 * setter on the same object without copying first.
 *
 * @note This is the default URL type returned by `ada::parse()`.
 *
 * @see url For an alternative using separate std::string instances
 */
struct url_aggregator : url_base {
  url_aggregator() = default;
  url_aggregator(const url_aggregator &u) = default;
  url_aggregator(url_aggregator &&u) noexcept = default;
  url_aggregator &operator=(url_aggregator &&u) noexcept = default;
  url_aggregator &operator=(const url_aggregator &u) = default;
  ~url_aggregator() override = default;

  /**
   * The setter functions follow the steps defined in the URL Standard.
   *
   * The url_aggregator has a single buffer that contains the entire normalized
   * URL. The various components are represented as offsets into that buffer.
   * When you call get_pathname(), for example, you get a std::string_view that
   * points into that buffer. If the url_aggregator is modified, the buffer may
   * be reallocated, and the std::string_view you obtained earlier may become
   * invalid. In particular, this implies that you cannot modify the URL using
   * a setter function with a std::string_view that points into the
   * url_aggregator E.g., the following is incorrect:
   * url->set_hostname(url->get_pathname()).
   * You must first copy the pathname to a separate string.
   * std::string pathname(url->get_pathname());
   * url->set_hostname(pathname);
   *
   * The caller is responsible for ensuring that the url_aggregator is not
   * modified while any std::string_view obtained from it is in use.
   */
  bool set_href(std::string_view input);
  bool set_host(std::string_view input);
  bool set_hostname(std::string_view input);
  bool set_protocol(std::string_view input);
  bool set_username(std::string_view input);
  bool set_password(std::string_view input);
  bool set_port(std::string_view input);
  bool set_pathname(std::string_view input);
  void set_search(std::string_view input);
  void set_hash(std::string_view input);

  /**
   * Validates whether the hostname is a valid domain according to RFC 1034.
   * @return `true` if the domain is valid, `false` otherwise.
   */
  [[nodiscard]] bool has_valid_domain() const noexcept override;

  /**
   * Returns the URL's origin (scheme + host + port for special URLs).
   * @return A newly allocated string containing the serialized origin.
   * @see https://url.spec.whatwg.org/#concept-url-origin
   */
  [[nodiscard]] std::string get_origin() const override;

  /**
   * Returns the full serialized URL (the href) as a string_view.
   * Does not allocate memory. The returned view becomes invalid if this
   * url_aggregator is modified or destroyed.
   * @return A string_view into the internal buffer.
   * @see https://url.spec.whatwg.org/#dom-url-href
   */
  [[nodiscard]] constexpr std::string_view get_href() const noexcept
      ada_lifetime_bound;

  /**
   * Returns the URL's username component.
   * Does not allocate memory. The returned view becomes invalid if this
   * url_aggregator is modified or destroyed.
   * @return A string_view of the username.
   * @see https://url.spec.whatwg.org/#dom-url-username
   */
  [[nodiscard]] std::string_view get_username() const ada_lifetime_bound;

  /**
   * Returns the URL's password component.
   * Does not allocate memory. The returned view becomes invalid if this
   * url_aggregator is modified or destroyed.
   * @return A string_view of the password.
   * @see https://url.spec.whatwg.org/#dom-url-password
   */
  [[nodiscard]] std::string_view get_password() const ada_lifetime_bound;

  /**
   * Returns the URL's port as a string (e.g., "8080").
   * Does not allocate memory. Returns empty view if no port is set.
   * The returned view becomes invalid if this url_aggregator is modified.
   * @return A string_view of the port.
   * @see https://url.spec.whatwg.org/#dom-url-port
   */
  [[nodiscard]] std::string_view get_port() const ada_lifetime_bound;

  /**
   * Returns the URL's fragment prefixed with '#' (e.g., "#section").
   * Does not allocate memory. Returns empty view if no fragment is set.
   * The returned view becomes invalid if this url_aggregator is modified.
   * @return A string_view of the hash.
   * @see https://url.spec.whatwg.org/#dom-url-hash
   */
  [[nodiscard]] std::string_view get_hash() const ada_lifetime_bound;

  /**
   * Returns the URL's host and port (e.g., "example.com:8080").
   * Does not allocate memory. Returns empty view if no host is set.
   * The returned view becomes invalid if this url_aggregator is modified.
   * @return A string_view of host:port.
   * @see https://url.spec.whatwg.org/#dom-url-host
   */
  [[nodiscard]] std::string_view get_host() const ada_lifetime_bound;

  /**
   * Returns the URL's hostname (without port).
   * Does not allocate memory. Returns empty view if no host is set.
   * The returned view becomes invalid if this url_aggregator is modified.
   * @return A string_view of the hostname.
   * @see https://url.spec.whatwg.org/#dom-url-hostname
   */
  [[nodiscard]] std::string_view get_hostname() const ada_lifetime_bound;

  /**
   * Returns the URL's path component.
   * Does not allocate memory. The returned view becomes invalid if this
   * url_aggregator is modified or destroyed.
   * @return A string_view of the pathname.
   * @see https://url.spec.whatwg.org/#dom-url-pathname
   */
  [[nodiscard]] constexpr std::string_view get_pathname() const
      ada_lifetime_bound;

  /**
   * Returns the byte length of the pathname without creating a string.
   * @return Size of the pathname in bytes.
   * @see https://url.spec.whatwg.org/#dom-url-pathname
   */
  [[nodiscard]] ada_really_inline uint32_t get_pathname_length() const noexcept;

  /**
   * Returns the URL's query string prefixed with '?' (e.g., "?foo=bar").
   * Does not allocate memory. Returns empty view if no query is set.
   * The returned view becomes invalid if this url_aggregator is modified.
   * @return A string_view of the search/query.
   * @see https://url.spec.whatwg.org/#dom-url-search
   */
  [[nodiscard]] std::string_view get_search() const ada_lifetime_bound;

  /**
   * Returns the URL's scheme followed by a colon (e.g., "https:").
   * Does not allocate memory. The returned view becomes invalid if this
   * url_aggregator is modified or destroyed.
   * @return A string_view of the protocol.
   * @see https://url.spec.whatwg.org/#dom-url-protocol
   */
  [[nodiscard]] std::string_view get_protocol() const ada_lifetime_bound;

  /**
   * Checks if the URL has credentials (non-empty username or password).
   * @return `true` if username or password is non-empty, `false` otherwise.
   */
  [[nodiscard]] ada_really_inline constexpr bool has_credentials()
      const noexcept;

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
   * @return A constant reference to the url_components struct.
   * @see https://github.com/servo/rust-url
   */
  [[nodiscard]] ada_really_inline const url_components &get_components()
      const noexcept;

  /**
   * Returns a JSON string representation of this URL for debugging.
   * @return A JSON-formatted string with all URL components.
   */
  [[nodiscard]] std::string to_string() const override;

  /**
   * Returns a visual diagram showing component boundaries in the URL.
   * Useful for debugging and understanding URL structure.
   * @return A multi-line string diagram.
   */
  [[nodiscard]] std::string to_diagram() const;

  /**
   * Validates internal consistency of component offsets (for debugging).
   * @return `true` if offsets are consistent, `false` if corrupted.
   */
  [[nodiscard]] constexpr bool validate() const noexcept;

  /**
   * Checks if the URL has an empty hostname (host is set but empty string).
   * @return `true` if host exists but is empty, `false` otherwise.
   */
  [[nodiscard]] constexpr bool has_empty_hostname() const noexcept;

  /**
   * Checks if the URL has a hostname (including empty hostnames).
   * @return `true` if host is present, `false` otherwise.
   */
  [[nodiscard]] constexpr bool has_hostname() const noexcept;

  /**
   * Checks if the URL has a non-empty username.
   * @return `true` if username is non-empty, `false` otherwise.
   */
  [[nodiscard]] constexpr bool has_non_empty_username() const noexcept;

  /**
   * Checks if the URL has a non-empty password.
   * @return `true` if password is non-empty, `false` otherwise.
   */
  [[nodiscard]] constexpr bool has_non_empty_password() const noexcept;

  /**
   * Checks if the URL has a non-default port explicitly specified.
   * @return `true` if a port is present, `false` otherwise.
   */
  [[nodiscard]] constexpr bool has_port() const noexcept;

  /**
   * Checks if the URL has a password component (may be empty).
   * @return `true` if password is present, `false` otherwise.
   */
  [[nodiscard]] constexpr bool has_password() const noexcept;

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

  /**
   * Removes the port from the URL.
   */
  inline void clear_port();

  /**
   * Removes the hash/fragment from the URL.
   */
  inline void clear_hash();

  /**
   * Removes the query/search string from the URL.
   */
  inline void clear_search() override;

 private:
  // helper methods
  friend void helpers::strip_trailing_spaces_from_opaque_path<url_aggregator>(
      url_aggregator &url);
  // parse_url methods
  friend url_aggregator parser::parse_url<url_aggregator>(
      std::string_view, const url_aggregator *);

  friend url_aggregator parser::parse_url_impl<url_aggregator, true>(
      std::string_view, const url_aggregator *);
  friend url_aggregator parser::parse_url_impl<url_aggregator, false>(
      std::string_view, const url_aggregator *);

#if ADA_INCLUDE_URL_PATTERN
  // url_pattern methods
  template <url_pattern_regex::regex_concept regex_provider>
  friend tl::expected<url_pattern<regex_provider>, errors>
  parse_url_pattern_impl(
      std::variant<std::string_view, url_pattern_init> &&input,
      const std::string_view *base_url, const url_pattern_options *options);
#endif  // ADA_INCLUDE_URL_PATTERN

  std::string buffer{};
  url_components components{};

  /**
   * Returns true if neither the search, nor the hash nor the pathname
   * have been set.
   * @return true if the buffer is ready to receive the path.
   */
  [[nodiscard]] ada_really_inline bool is_at_path() const noexcept;

  inline void add_authority_slashes_if_needed();

  /**
   * To optimize performance, you may indicate how much memory to allocate
   * within this instance.
   */
  constexpr void reserve(uint32_t capacity);

  ada_really_inline size_t parse_port(std::string_view view,
                                      bool check_trailing_content) override;

  ada_really_inline size_t parse_port(std::string_view view) override {
    return this->parse_port(view, false);
  }

  /**
   * Return true on success. The 'in_place' parameter indicates whether the
   * the string_view input is pointing in the buffer. When in_place is false,
   * we must nearly always update the buffer.
   * @see https://url.spec.whatwg.org/#concept-ipv4-parser
   */
  [[nodiscard]] bool parse_ipv4(std::string_view input, bool in_place);

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

  ada_really_inline void parse_path(std::string_view input);

  /**
   * A URL cannot have a username/password/port if its host is null or the empty
   * string, or its scheme is "file".
   */
  [[nodiscard]] constexpr bool cannot_have_credentials_or_port() const;

  template <bool override_hostname = false>
  bool set_host_or_hostname(std::string_view input);

  ada_really_inline bool parse_host(std::string_view input);

  inline void update_base_authority(std::string_view base_buffer,
                                    const url_components &base);
  inline void update_unencoded_base_hash(std::string_view input);
  inline void update_base_hostname(std::string_view input);
  inline void update_base_search(std::string_view input);
  inline void update_base_search(std::string_view input,
                                 const uint8_t *query_percent_encode_set);
  inline void update_base_pathname(std::string_view input);
  inline void update_base_username(std::string_view input);
  inline void append_base_username(std::string_view input);
  inline void update_base_password(std::string_view input);
  inline void append_base_password(std::string_view input);
  inline void update_base_port(uint32_t input);
  inline void append_base_pathname(std::string_view input);
  [[nodiscard]] inline uint32_t retrieve_base_port() const;
  constexpr void clear_hostname();
  constexpr void clear_password();
  constexpr void clear_pathname() override;
  [[nodiscard]] constexpr bool has_dash_dot() const noexcept;
  void delete_dash_dot();
  inline void consume_prepared_path(std::string_view input);
  template <bool has_state_override = false>
  [[nodiscard]] ada_really_inline bool parse_scheme_with_colon(
      std::string_view input);
  ada_really_inline uint32_t replace_and_resize(uint32_t start, uint32_t end,
                                                std::string_view input);
  [[nodiscard]] constexpr bool has_authority() const noexcept;
  constexpr void set_protocol_as_file();
  inline void set_scheme(std::string_view new_scheme);
  /**
   * Fast function to set the scheme from a view with a colon in the
   * buffer, does not change type.
   */
  inline void set_scheme_from_view_with_colon(
      std::string_view new_scheme_with_colon);
  inline void copy_scheme(const url_aggregator &u);

  inline void update_host_to_base_host(const std::string_view input);

};  // url_aggregator

inline std::ostream &operator<<(std::ostream &out, const url &u);
}  // namespace ada

#endif
