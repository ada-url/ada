/**
 * @file url.h
 * @brief Declaration for the URL
 */
#ifndef ADA_URL_H
#define ADA_URL_H

#include "ada/checkers.h"
#include "ada/scheme.h"
#include "ada/common_defs.h"
#include "ada/serializers.h"
#include "ada/unicode.h"
#include "ada/log.h"

#include <algorithm>
#include <charconv>
#include <optional>
#include <iostream>
#include <string>
#include <string_view>

namespace ada {
  /**
   * @brief Generic URL struct.
   *
   * @details To disambiguate from a valid URL string it can also be referred to as a URL record.
   * A URL is a struct that represents a universal identifier.
   * @see https://url.spec.whatwg.org/#url-representation
   */
  struct url {
    url() = default;
    url(const url &u) = default;
    url(url &&u) noexcept = default;
    url &operator=(url &&u) noexcept = default;
    url &operator=(const url &u) = default;
    ADA_ATTRIBUTE_NOINLINE ~url() = default;

    /**
     * @private
     * A URL’s username is an ASCII string identifying a username. It is initially the empty string.
     */
    std::string username{};

    /**
     * @private
     * A URL’s password is an ASCII string identifying a password. It is initially the empty string.
     */
    std::string password{};

    /**
     * @private
     * A URL’s host is null or a host. It is initially null.
     */
    std::optional<std::string> host{};

    /**
     * @private
     * A URL’s port is either null or a 16-bit unsigned integer that identifies a networking port. It is initially null.
     */
    std::optional<uint16_t> port{};

    /**
     * @private
     * A URL’s path is either an ASCII string or a list of zero or more ASCII strings, usually identifying a location.
     */
    std::string path{};

    /**
     * @private
     * A URL’s query is either null or an ASCII string. It is initially null.
     */
    std::optional<std::string> query{};

    /**
     * @private
     * A URL’s fragment is either null or an ASCII string that can be used for further processing on the resource
     * the URL’s other components identify. It is initially null.
     */
    std::optional<std::string> fragment{};

    /**
     * @see https://url.spec.whatwg.org/#dom-url-href
     * @see https://url.spec.whatwg.org/#concept-url-serializer
     */
    [[nodiscard]] std::string get_href() const noexcept;

    /**
     * The origin getter steps are to return the serialization of this’s URL’s origin. [HTML]
     * @see https://url.spec.whatwg.org/#concept-url-origin
     */
    [[nodiscard]] std::string get_origin() const noexcept;

    /**
     * The protocol getter steps are to return this’s URL’s scheme, followed by U+003A (:).
     * @see https://url.spec.whatwg.org/#dom-url-protocol
     */
    [[nodiscard]] std::string get_protocol() const noexcept;

    /**
     * Return url’s host, serialized, followed by U+003A (:) and url’s port, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-host
     */
    [[nodiscard]] std::string get_host() const noexcept;

    /**
     * Return this’s URL’s host, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-hostname
     */
    [[nodiscard]] std::string get_hostname() const noexcept;

    /**
     * The pathname getter steps are to return the result of URL path serializing this’s URL.
     * @see https://url.spec.whatwg.org/#dom-url-pathname
     */
    [[nodiscard]] std::string get_pathname() const noexcept;

    /**
     * Return U+003F (?), followed by this’s URL’s query.
     * @see https://url.spec.whatwg.org/#dom-url-search
     */
    [[nodiscard]] std::string get_search() const noexcept;

    /**
     * The username getter steps are to return this’s URL’s username.
     * @see https://url.spec.whatwg.org/#dom-url-username
     */
    [[nodiscard]] std::string get_username() const noexcept;

    /**
     * @return Returns true on successful operation.
     * @see https://url.spec.whatwg.org/#dom-url-username
     */
    bool set_username(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-password
     */
    bool set_password(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-port
     */
    bool set_port(const std::string_view input);

    /**
     * This function always succeeds.
     * @see https://url.spec.whatwg.org/#dom-url-hash
     */
    void set_hash(const std::string_view input);

    /**
     * This function always succeeds.
     * @see https://url.spec.whatwg.org/#dom-url-search
     */
    void set_search(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-search
     */
    bool set_pathname(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-host
     */
    bool set_host(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-hostname
     */
    bool set_hostname(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-protocol
     */
    bool set_protocol(const std::string_view input);

    /**
     * @see https://url.spec.whatwg.org/#dom-url-href
     */
    bool set_href(const std::string_view input);

    /**
     * The password getter steps are to return this’s URL’s password.
     * @see https://url.spec.whatwg.org/#dom-url-password
     */
    [[nodiscard]] std::string get_password() const noexcept;

    /**
     * Return this’s URL’s port, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-port
     */
    [[nodiscard]] std::string get_port() const noexcept;

    /**
     * Return U+0023 (#), followed by this’s URL’s fragment.
     * @see https://url.spec.whatwg.org/#dom-url-hash
     */
    [[nodiscard]] std::string get_hash() const noexcept;

    /**
     * Returns true if this URL has a valid domain as per RFC 1034 and
     * corresponding specifications. Among other things, it requires
     * that the domain string has fewer than 255 octets.
     */
    [[nodiscard]] bool has_valid_domain() const noexcept;

    /**
     * Used for returning the validity from the result of the URL parser.
     */
    bool is_valid{true};

    /**
     * A URL has an opaque path if its path is a string.
     */
    bool has_opaque_path{false};

    /**
     * A URL includes credentials if its username or password is not the empty string.
     */
    [[nodiscard]] ada_really_inline bool includes_credentials() const noexcept;

    /**
     * A URL is special if its scheme is a special scheme. A URL is not special if its scheme is not a special scheme.
     */
    [[nodiscard]] ada_really_inline bool is_special() const noexcept;

    /**
     * @private
     *
     * Return the 'special port' if the URL is special and not 'file'.
     * Returns 0 otherwise.
     */
    [[nodiscard]] inline uint16_t get_special_port() const;

    /**
     * @private
     *
     * Return the scheme type. Note that it is faster to do
     * get_scheme_type() == ada::scheme::type::FILE than to do
     * get_scheme() == "file", since the former is a direct integer comparison,
     * while the other involves a (cheap) string test.
     */
    [[nodiscard]] ada_really_inline ada::scheme::type get_scheme_type() const noexcept;

    /**
     * @private
     *
     * Get the default port if the url's scheme has one, returns 0 otherwise.
     */
    [[nodiscard]] ada_really_inline uint16_t scheme_default_port() const noexcept;
    /**
     * @private
     *
     * A URL cannot have a username/password/port if its host is null or the empty string, or its scheme is "file".
     */
    [[nodiscard]] inline bool cannot_have_credentials_or_port() const;

    /**
     * @private
     *
     * Parse a port (16-bit decimal digit) from the provided input.
     * We assume that the input does not contain spaces or tabs
     * within the ASCII digits.
     * It returns how many bytes were consumed when a number is successfully parsed.
     * @return On failure, it returns zero.
     * @see https://url.spec.whatwg.org/#host-parsing
     */
    ada_really_inline size_t parse_port(std::string_view view, bool check_trailing_content = false) noexcept;

    /**
     * @private
     *
     * Return a string representing the scheme. Note that get_scheme_type() should often be used instead.
     * @see https://url.spec.whatwg.org/#dom-url-protocol
     */
    [[nodiscard]] inline std::string_view get_scheme() const noexcept;
    /**
     * Set the scheme for this URL. The provided scheme should be a valid
     * scheme string, be lower-cased, not contain spaces or tabs. It should
     * have no spurious trailing or leading content.
     */
    inline void set_scheme(std::string&& new_scheme) noexcept;

    /**
     * @private
     *
     * Take the scheme from another URL. The scheme string is moved from the
     * provided url.
     */
    inline void copy_scheme(ada::url&& u) noexcept;

    /**
     * @private
     *
     * Take the scheme from another URL. The scheme string is copied from the
     * provided url.
     */
    inline void copy_scheme(const ada::url& u);

    /**
     * @private
     *
     * Parse the host from the provided input. We assume that
     * the input does not contain spaces or tabs. Control
     * characters and spaces are not trimmed (they should have
     * been removed if needed).
     * Return true on success.
     * @see https://url.spec.whatwg.org/#host-parsing
     */
    [[nodiscard]] ada_really_inline bool parse_host(std::string_view input);

    /**
     * @private
     *
     * Parse the path from the provided input.
     * Return true on success. Control characters not
     * trimmed from the ends (they should have
     * been removed if needed).
     *
     * The input is expected to be UTF-8.
     *
     * @see https://url.spec.whatwg.org/
     */
    [[nodiscard]] ada_really_inline bool parse_path(const std::string_view input);

    /**
     * @private
     */
    template <bool has_state_override = false>
    [[nodiscard]] ada_really_inline bool parse_scheme(const std::string_view input);

    /**
     * Returns a JSON string representation of this URL.
     */
    std::string to_string() const;

  private:

    /**
     * @private
     *
     * Return true on success.
     * @see https://url.spec.whatwg.org/#concept-ipv4-parser
     */
    [[nodiscard]] bool parse_ipv4(std::string_view input);

    /**
     * @private
     *
     * Return true on success.
     * @see https://url.spec.whatwg.org/#concept-ipv6-parser
     */
    [[nodiscard]] bool parse_ipv6(std::string_view input);

    /**
     * @private
     *
     * Return true on success.
     * @see https://url.spec.whatwg.org/#concept-opaque-host-parser
     */
    [[nodiscard]] bool parse_opaque_host(std::string_view input);

    /**
     * @private
     * 
     * Sets the host or hostname according to override condition.
     * Return true on success.
     * @see https://url.spec.whatwg.org/#hostname-state
     */

    [[nodiscard]] bool set_host_or_hostname(std::string_view input, bool override_hostname);

    /**
     * @private
     */
    ada::scheme::type type{ada::scheme::type::NOT_SPECIAL};

    /**
     * @private
     *
     * A URL’s scheme is an ASCII string that identifies the type of URL and can be used to dispatch a
     * URL for further processing after parsing. It is initially the empty string.
     * We only set non_special_scheme when the scheme is non-special, otherwise we avoid constructing
     * string.
     *
     * Special schemes are stored in ada::scheme::details::is_special_list so we typically do not need
     * to store them in each url instance.
     */
    std::string non_special_scheme{};

  }; // struct url


  inline std::ostream& operator<<(std::ostream& out, const ada::url& u);
} // namespace ada

#endif // ADA_URL_H
