/**
 * @file url_aggregator.h
 * @brief Declaration for the basic URL definitions
 */
#ifndef ADA_URL_AGGREGATOR_H
#define ADA_URL_AGGREGATOR_H

#include <string>
#include <string_view>

#include "ada/common_defs.h"
#include "ada/url_base.h"
#include "ada/url_components.h"

namespace ada {

/**
 * @brief Lightweight URL struct.
 *
 * @details The url_aggregator class aims to minimize temporary memory
 * allocation while representing a parsed URL. Internally, it contains a single
 * normalized URL (the href), and it makes available the components, mostly
 * using std::string_view.
 */
struct url_aggregator : url_base {
  url_aggregator() = default;
  url_aggregator(const url_aggregator &u) = default;
  url_aggregator(url_aggregator &&u) noexcept = default;
  url_aggregator &operator=(url_aggregator &&u) noexcept = default;
  url_aggregator &operator=(const url_aggregator &u) = default;
  ~url_aggregator() override = default;

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

  [[nodiscard]] bool has_valid_domain() const noexcept override;
  /**
   * The origin getter steps are to return the serialization of this's URL's
   * origin. [HTML]
   * @return a newly allocated string.
   * @see https://url.spec.whatwg.org/#concept-url-origin
   */
  [[nodiscard]] std::string get_origin() const noexcept override;
  /**
   * Return the normalized string.
   * This function does not allocate memory.
   * It is highly efficient.
   * @return a constant reference to the underlying normalized URL.
   * @see https://url.spec.whatwg.org/#dom-url-href
   * @see https://url.spec.whatwg.org/#concept-url-serializer
   */
  [[nodiscard]] inline std::string_view get_href() const noexcept
      ada_lifetime_bound;
  /**
   * The username getter steps are to return this's URL's username.
   * This function does not allocate memory.
   * @return a lightweight std::string_view.
   * @see https://url.spec.whatwg.org/#dom-url-username
   */
  [[nodiscard]] std::string_view get_username() const noexcept
      ada_lifetime_bound;
  /**
   * The password getter steps are to return this's URL's password.
   * This function does not allocate memory.
   * @return a lightweight std::string_view.
   * @see https://url.spec.whatwg.org/#dom-url-password
   */
  [[nodiscard]] std::string_view get_password() const noexcept
      ada_lifetime_bound;
  /**
   * Return this's URL's port, serialized.
   * This function does not allocate memory.
   * @return a lightweight std::string_view.
   * @see https://url.spec.whatwg.org/#dom-url-port
   */
  [[nodiscard]] std::string_view get_port() const noexcept ada_lifetime_bound;
  /**
   * Return U+0023 (#), followed by this's URL's fragment.
   * This function does not allocate memory.
   * @return a lightweight std::string_view..
   * @see https://url.spec.whatwg.org/#dom-url-hash
   */
  [[nodiscard]] std::string_view get_hash() const noexcept ada_lifetime_bound;
  /**
   * Return url's host, serialized, followed by U+003A (:) and url's port,
   * serialized.
   * This function does not allocate memory.
   * When there is no host, this function returns the empty view.
   * @return a lightweight std::string_view.
   * @see https://url.spec.whatwg.org/#dom-url-host
   */
  [[nodiscard]] std::string_view get_host() const noexcept ada_lifetime_bound;
  /**
   * Return this's URL's host, serialized.
   * This function does not allocate memory.
   * When there is no host, this function returns the empty view.
   * @return a lightweight std::string_view.
   * @see https://url.spec.whatwg.org/#dom-url-hostname
   */
  [[nodiscard]] std::string_view get_hostname() const noexcept
      ada_lifetime_bound;
  /**
   * The pathname getter steps are to return the result of URL path serializing
   * this's URL.
   * This function does not allocate memory.
   * @return a lightweight std::string_view.
   * @see https://url.spec.whatwg.org/#dom-url-pathname
   */
  [[nodiscard]] std::string_view get_pathname() const noexcept
      ada_lifetime_bound;
  /**
   * Compute the pathname length in bytes without instantiating a view or a
   * string.
   * @return size of the pathname in bytes
   * @see https://url.spec.whatwg.org/#dom-url-pathname
   */
  [[nodiscard]] ada_really_inline uint32_t get_pathname_length() const noexcept;
  /**
   * Return U+003F (?), followed by this's URL's query.
   * This function does not allocate memory.
   * @return a lightweight std::string_view.
   * @see https://url.spec.whatwg.org/#dom-url-search
   */
  [[nodiscard]] std::string_view get_search() const noexcept ada_lifetime_bound;
  /**
   * The protocol getter steps are to return this's URL's scheme, followed by
   * U+003A (:).
   * This function does not allocate memory.
   * @return a lightweight std::string_view.
   * @see https://url.spec.whatwg.org/#dom-url-protocol
   */
  [[nodiscard]] std::string_view get_protocol() const noexcept
      ada_lifetime_bound;

  /**
   * A URL includes credentials if its username or password is not the empty
   * string.
   */
  [[nodiscard]] ada_really_inline bool has_credentials() const noexcept;

  /**
   * Useful for implementing efficient serialization for the URL.
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
   *
   * Inspired after servo/url
   *
   * @return a constant reference to the underlying component attribute.
   *
   * @see
   * https://github.com/servo/rust-url/blob/b65a45515c10713f6d212e6726719a020203cc98/url/src/quirks.rs#L31
   */
  [[nodiscard]] ada_really_inline const ada::url_components &get_components()
      const noexcept;
  /**
   * Returns a string representation of this URL.
   */
  [[nodiscard]] std::string to_string() const override;
  /**
   * Returns a string diagram of this URL.
   */
  [[nodiscard]] std::string to_diagram() const;

  /**
   * Verifies that the parsed URL could be valid. Useful for debugging purposes.
   * @return true if the URL is valid, otherwise return true of the offsets are
   * possible.
   */
  [[nodiscard]] bool validate() const noexcept;

  /** @return true if it has an host but it is the empty string */
  [[nodiscard]] inline bool has_empty_hostname() const noexcept;
  /** @return true if it has a host (included an empty host) */
  [[nodiscard]] inline bool has_hostname() const noexcept;
  /** @return true if the URL has a non-empty username */
  [[nodiscard]] inline bool has_non_empty_username() const noexcept;
  /** @return true if the URL has a non-empty password */
  [[nodiscard]] inline bool has_non_empty_password() const noexcept;
  /** @return true if the URL has a (non default) port */
  [[nodiscard]] inline bool has_port() const noexcept;
  /** @return true if the URL has a password */
  [[nodiscard]] inline bool has_password() const noexcept;
  /** @return true if the URL has a hash component */
  [[nodiscard]] inline bool has_hash() const noexcept override;
  /** @return true if the URL has a search component */
  [[nodiscard]] inline bool has_search() const noexcept override;

  inline void clear_port();
  inline void clear_hash();
  inline void clear_search() override;

 private:
  friend ada::url_aggregator ada::parser::parse_url<ada::url_aggregator>(
      std::string_view, const ada::url_aggregator *);
  friend void ada::helpers::strip_trailing_spaces_from_opaque_path<
      ada::url_aggregator>(ada::url_aggregator &url) noexcept;
  friend ada::url_aggregator ada::parser::parse_url_impl<
      ada::url_aggregator, true>(std::string_view, const ada::url_aggregator *);
  friend ada::url_aggregator
  ada::parser::parse_url_impl<ada::url_aggregator, false>(
      std::string_view, const ada::url_aggregator *);

  std::string buffer{};
  url_components components{};

  /**
   * Returns true if neither the search, nor the hash nor the pathname
   * have been set.
   * @return true if the buffer is ready to receive the path.
   */
  [[nodiscard]] ada_really_inline bool is_at_path() const noexcept;

  inline void add_authority_slashes_if_needed() noexcept;

  /**
   * To optimize performance, you may indicate how much memory to allocate
   * within this instance.
   */
  inline void reserve(uint32_t capacity);

  ada_really_inline size_t parse_port(
      std::string_view view, bool check_trailing_content) noexcept override;

  ada_really_inline size_t parse_port(std::string_view view) noexcept override {
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
  [[nodiscard]] inline bool cannot_have_credentials_or_port() const;

  template <bool override_hostname = false>
  bool set_host_or_hostname(std::string_view input);

  ada_really_inline bool parse_host(std::string_view input);

  inline void update_base_authority(std::string_view base_buffer,
                                    const ada::url_components &base);
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
  inline void clear_hostname();
  inline void clear_password();
  inline void clear_pathname() override;
  [[nodiscard]] inline bool has_dash_dot() const noexcept;
  void delete_dash_dot();
  inline void consume_prepared_path(std::string_view input);
  template <bool has_state_override = false>
  [[nodiscard]] ada_really_inline bool parse_scheme_with_colon(
      std::string_view input);
  ada_really_inline uint32_t replace_and_resize(uint32_t start, uint32_t end,
                                                std::string_view input);
  [[nodiscard]] inline bool has_authority() const noexcept;
  inline void set_protocol_as_file();
  inline void set_scheme(std::string_view new_scheme) noexcept;
  /**
   * Fast function to set the scheme from a view with a colon in the
   * buffer, does not change type.
   */
  inline void set_scheme_from_view_with_colon(
      std::string_view new_scheme_with_colon) noexcept;
  inline void copy_scheme(const url_aggregator &u) noexcept;

};  // url_aggregator

inline std::ostream &operator<<(std::ostream &out, const ada::url &u);
}  // namespace ada

#endif
