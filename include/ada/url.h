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
#include "ada/url_components.h"
#include "ada/url_base.h"

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
  struct url: url_base {

    url() = default;
    url(const url &u) = default;
    url(url &&u) noexcept = default;
    url &operator=(url &&u) noexcept = default;
    url &operator=(const url &u) = default;
    ~url() = default;

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

    [[nodiscard]] std::string get_origin() const noexcept;
    [[nodiscard]] std::string get_href() const noexcept;
    [[nodiscard]] std::string get_username() const noexcept;
    [[nodiscard]] std::string get_password() const noexcept;
    [[nodiscard]] std::string get_port() const noexcept;
    [[nodiscard]] std::string get_hash() const noexcept;
    [[nodiscard]] std::string get_host() const noexcept;
    [[nodiscard]] std::string get_hostname() const noexcept;
    [[nodiscard]] std::string get_pathname() const noexcept;
    [[nodiscard]] std::string get_search() const noexcept;
    [[nodiscard]] std::string get_protocol() const noexcept;

    bool set_href(const std::string_view input);
    bool set_host(const std::string_view input);
    bool set_hostname(const std::string_view input);

    [[nodiscard]] ada_really_inline bool includes_credentials() const noexcept;
    [[nodiscard]] inline bool cannot_have_credentials_or_port() const;

    /**
     * @private
     * 
     * Sets the host or hostname according to override condition.
     * Return true on success.
     * @see https://url.spec.whatwg.org/#hostname-state
     */
    bool set_host_or_hostname(std::string_view input, bool override_hostname);

    /** @private */
    inline void update_base_hash(std::string_view input);
    /** @private */
    inline void update_base_search(std::optional<std::string> input);
    /** @private */
    inline void update_base_pathname(const std::string_view input);
    /** @private */
    inline void update_base_username(const std::string_view input);
    /** @private */
    inline void update_base_password(const std::string_view input);
    /** @private */
    inline void update_base_port(std::optional<uint16_t> input);
    /** @private */
    inline std::optional<uint16_t> retrieve_base_port() const;
    /** @private */
    inline std::string retrieve_base_pathname() const;
    /** @private */
    inline void clear_base_hash();
    /** @private */
    inline bool base_hostname_has_value() const;
    /** @private */
    inline bool base_fragment_has_value() const;
    /** @private */
    inline bool base_search_has_value() const;
    /** @private */
    inline bool base_port_has_value() const;

    /**
     * Returns true if this URL has a valid domain as per RFC 1034 and
     * corresponding specifications. Among other things, it requires
     * that the domain string has fewer than 255 octets.
     */
    [[nodiscard]] bool has_valid_domain() const noexcept;

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

    std::string to_string() const;

    [[nodiscard]] ada_really_inline ada::url_components get_components() noexcept;

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

  }; // struct url


  inline std::ostream& operator<<(std::ostream& out, const ada::url& u);
} // namespace ada

#endif // ADA_URL_H
