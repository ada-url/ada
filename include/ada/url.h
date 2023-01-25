/**
 * @file url.h
 * @brief Definitions for the URL
 */
#ifndef ADA_URL_H
#define ADA_URL_H

#include "ada/checkers.h"
#include "ada/scheme.h"
#include "ada/common_defs.h"
#include "ada/serializers.h"
#include "ada/unicode.h"

#include <charconv>
#include <optional>
#include <iostream>
#include <string>
#include <string_view>

namespace ada {
  /**
   * @brief A URL is a struct that represents a universal identifier.
   * @details To disambiguate from a valid URL string it can also be referred to as a URL record.
   *
   * @see https://url.spec.whatwg.org/#url-representation
   */
  struct url {
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
    [[nodiscard]] std::string get_href() const noexcept {
      return get_protocol()
        + (host.has_value() ?
          "//" + username + (password.empty() ? "" : ":" + password) + (includes_credentials() ? "@" : "") + host.value() +
          (port.has_value() ? ":" + get_port() : "")
          : "")
        + get_pathname()
        + get_search()
        + get_hash();
    }

    /**
     * The origin getter steps are to return the serialization of this’s URL’s origin. [HTML]
     * @see https://url.spec.whatwg.org/#concept-url-origin
     */
    [[nodiscard]] std::string get_origin() const noexcept {
      if (is_special()) {
        // Return the tuple origin (url’s scheme, url’s host, url’s port, null).
        return get_protocol() + "//" + get_host();
      }

      if (get_scheme() == "blob") {
        // TODO: Implement blob origin serializer
      }

      // Return a new opaque origin.
      return "null";
    }

    /**
     * The protocol getter steps are to return this’s URL’s scheme, followed by U+003A (:).
     * @see https://url.spec.whatwg.org/#dom-url-protocol
     */
    [[nodiscard]] std::string get_protocol() const noexcept {
      return std::string(get_scheme()) + ":";
    }

    /**
     * Return url’s host, serialized, followed by U+003A (:) and url’s port, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-host
     */
    [[nodiscard]] std::string get_host() const noexcept {
      if (!host.has_value()) { return ""; }
      return host.value() + (port.has_value() ? ":" + get_port() : "");
    }

    /**
     * Return this’s URL’s host, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-hostname
     */
    [[nodiscard]] std::string get_hostname() const noexcept {
      return host.value_or("");
    }

    /**
     * The pathname getter steps are to return the result of URL path serializing this’s URL.
     * @see https://url.spec.whatwg.org/#dom-url-pathname
     */
    [[nodiscard]] std::string get_pathname() const noexcept {
      return path;
    }

    /**
     * Return U+003F (?), followed by this’s URL’s query.
     * @see https://url.spec.whatwg.org/#dom-url-search
     */
    [[nodiscard]] std::string get_search() const noexcept {
      return query.has_value() ? "?" + query.value() : "";
    }

    /**
     * The username getter steps are to return this’s URL’s username.
     * @see https://url.spec.whatwg.org/#dom-url-username
     */
    [[nodiscard]] std::string get_username() const noexcept {
      return username;
    }

    /**
     * @see https://url.spec.whatwg.org/#dom-url-username
     */
    void set_username(const std::string_view input) {
      if (cannot_have_credentials_or_port()) return;
      username = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
    }

    /**
     * @see https://url.spec.whatwg.org/#dom-url-password
     */
    void set_password(const std::string_view input) {
      if (cannot_have_credentials_or_port()) return;
      password = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
    }

    /**
     * The password getter steps are to return this’s URL’s password.
     * @see https://url.spec.whatwg.org/#dom-url-password
     */
    [[nodiscard]] std::string get_password() const noexcept {
      return password;
    }

    /**
     * Return this’s URL’s port, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-port
     */
    [[nodiscard]] std::string get_port() const noexcept {
      return port.has_value() ? std::to_string(port.value()) : "";
    }

    /**
     * Return U+0023 (#), followed by this’s URL’s fragment.
     * @see https://url.spec.whatwg.org/#dom-url-hash
     */
    [[nodiscard]] std::string get_hash() const noexcept {
      return fragment.has_value() ? "#" + fragment.value() : "";
    }

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
    [[nodiscard]] ada_really_inline bool includes_credentials() const noexcept {
      return !username.empty() || !password.empty();
    }

    /**
     * A URL is special if its scheme is a special scheme. A URL is not special if its scheme is not a special scheme.
     */
    [[nodiscard]] ada_really_inline bool is_special() const noexcept {
      return type != ada::scheme::NOT_SPECIAL;
    }

    /**
     * @private
     *
     * Return the 'special port' if the URL is special and not 'file'.
     * Returns 0 otherwise.
     */
    [[nodiscard]] uint16_t get_special_port() const {
      return ada::scheme::get_special_port(type);
    }

    /**
     * @private
     *
     * Return the scheme type. Note that it is faster to do
     * get_scheme_type() == ada::scheme::type::FILE than to do
     * get_scheme() == "file", since the former is a direct integer comparison,
     * while the other involves a (cheap) string test.
     */
    [[nodiscard]] ada_really_inline ada::scheme::type get_scheme_type() const noexcept {
      return type;
    }

    /**
     * @private
     *
     * Get the default port if the url's scheme has one, returns 0 otherwise.
     */
    [[nodiscard]] ada_really_inline uint16_t scheme_default_port() const noexcept {
      return scheme::get_special_port(type);
    }

    /**
     * @private
     *
     * A URL cannot have a username/password/port if its host is null or the empty string, or its scheme is "file".
     */
    [[nodiscard]] bool cannot_have_credentials_or_port() const {
      return !host.has_value() || host.value().empty() || type == ada::scheme::type::FILE;
    }
    /** For development purposes, we want to know when a copy is made. */
    url() = default;
#if ADA_DEVELOP_MODE
    url(const url &u) = delete; /**TODO: reenable this before the first release. */
#else
    url(const url &u) = default;
#endif
    url(url &&u) = default;
    url &operator=(url &&u) = default;
#if ADA_DEVELOP_MODE
    url &operator=(const url &u) = delete;
#else
    url &operator=(const url &u) = default;
#endif
    ADA_ATTRIBUTE_NOINLINE ~url() = default;

    /**
     * @private
     *
     * Parse a port (16-bit decimal digit) from the provided input.
     * We assume that the input does not contain spaces or tabs
     * within the ASCII digits.
     * It returns how many bytes were consumed when a number is successfully parsed.
     * @see https://url.spec.whatwg.org/#host-parsing
     */
    ada_really_inline size_t parse_port(std::string_view view) noexcept {
#if ADA_LOGGING
          std::cout << "parse_port('" << view << "') "<< view.size()  << std::endl;
#endif
          uint16_t parsed_port{};
          auto r = std::from_chars(view.data(), view.data() + view.size(), parsed_port);
          if(r.ec == std::errc::result_out_of_range) {
#if ADA_LOGGING
            std::cout << "parse_port: std::errc::result_out_of_range" << std::endl;
#endif
            is_valid = false;
            return 0;
          }
#if ADA_LOGGING
          std::cout << "parse_port: " << parsed_port << std::endl;
#endif
          port = (r.ec == std::errc() && scheme_default_port() != parsed_port) ?
            std::optional<uint16_t>(parsed_port) : std::nullopt;
          const size_t consumed = size_t(r.ptr - view.data());
#if ADA_LOGGING
          std::cout << "parse_port: consumed = " << consumed << std::endl;
#endif
          is_valid &= (consumed == view.size() || view[consumed] == '/' || view[consumed] == '?' || (is_special() && view[consumed] == '\\'));
#if ADA_LOGGING
          std::cout << "parse_port: is_valid = " << is_valid << std::endl;
#endif
          return consumed;
    }

    /**
     * @private
     *
     * Return a string representing the scheme. Note that get_scheme_type() should often be used instead.
     * @see https://url.spec.whatwg.org/#dom-url-protocol
     */
    [[nodiscard]] std::string_view get_scheme() const noexcept {
      if(is_special()) { return ada::scheme::details::is_special_list[type]; }
      // We only move the 'scheme' if it is non-special.
      return non_special_scheme;
    }

    /**
     * Set the scheme for this URL. The provided scheme should be a valid
     * scheme string, be lower-cased, not contain spaces or tabs. It should
     * have no spurious trailing or leading content.
     */
    void set_scheme(std::string&& new_scheme) {
      type = ada::scheme::get_scheme_type(new_scheme);
      // We only move the 'scheme' if it is non-special.
      if(!is_special()) {
        non_special_scheme = new_scheme;
      }
    }

    /**
     * @private
     *
     * Take the scheme from another URL. The scheme string is moved from the
     * provided url.
     */
    void copy_scheme(ada::url&& u) {
      non_special_scheme = u.non_special_scheme;
      type = u.type;
    }

    /**
     * @private
     *
     * Take the scheme from another URL. The scheme string is copied from the
     * provided url.
     */
    void copy_scheme(const ada::url& u) {
      non_special_scheme = u.non_special_scheme;
      type = u.type;
    }

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
    ada_really_inline bool parse_host(const std::string_view input);

    /**
     * @private
     *
     * Parse the path from the provided input.
     * Return true on success. Control characters not
     * trimmed from the ends (they should have
     * been removed if needed).
     * @see https://url.spec.whatwg.org/#host-parsing
     */
    ada_really_inline bool parse_path(const std::string_view input);

    /**
     * @private
     *
     * Parse the path from the provided input. It should have been
     * 'prepared' (e.g., it cannot contain tabs and spaces). See
     * parse_path.
     *
     * Return true on success.
     * @see https://url.spec.whatwg.org/#host-parsing
     */
    ada_really_inline bool parse_prepared_path(const std::string_view input);

    /**
     * @private
     */
    template <bool has_state_override = false>
    ada_really_inline bool parse_scheme(const std::string_view input);

    /**
     * Returns a string representation of this URL.  (Useful for debugging.)
     */
    std::string to_string();

  private:

    /**
     * @private
     *
     * Return true on success.
     * @see https://url.spec.whatwg.org/#concept-ipv4-parser
     */
    bool parse_ipv4(std::string_view input);

    /**
     * @private
     *
     * Return true on success.
     * @see https://url.spec.whatwg.org/#concept-ipv6-parser
     */
    bool parse_ipv6(std::string_view input);

    /**
     * @private
     *
     * Return true on success.
     * @see https://url.spec.whatwg.org/#concept-opaque-host-parser
     */
    bool parse_opaque_host(std::string_view input) noexcept;

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

} // namespace ada

#endif // ADA_URL_H
