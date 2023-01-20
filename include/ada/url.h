#ifndef ADA_URL_H
#define ADA_URL_H

#include "checkers.h"
#include "scheme.h"
#include "common_defs.h"
#include "serializers.h"

#include <charconv>
#include <optional>
#include <iostream>
#include <string>
#include <string_view>

namespace ada {
  /**
   * A URL is a struct that represents a universal identifier.
   * To disambiguate from a valid URL string it can also be referred to as a URL record.
   *
   * @see https://url.spec.whatwg.org/#url-representation
   */
  struct url {
    /**
     * A URL’s username is an ASCII string identifying a username. It is initially the empty string.
     */
    std::string username{};


    /**
     * A URL’s password is an ASCII string identifying a password. It is initially the empty string.
     */
    std::string password{};

    /**
     * A URL’s host is null or a host. It is initially null.
     */
    std::optional<std::string> host{};

    /**
     * A URL’s port is either null or a 16-bit unsigned integer that identifies a networking port. It is initially null.
     */
    std::optional<uint16_t> port{};

    /**
     * A URL’s path is either an ASCII string or a list of zero or more ASCII strings, usually identifying a location.
     */
    std::string path{};

    /**
     * A URL’s query is either null or an ASCII string. It is initially null.
     */
    std::optional<std::string> query{};

    /**
     * A URL’s fragment is either null or an ASCII string that can be used for further processing on the resource
     * the URL’s other components identify. It is initially null.
     */
    std::optional<std::string> fragment{};

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
    [[nodiscard]] ada_really_inline  bool is_special() const noexcept {
      return type != ada::scheme::NOT_SPECIAL;
    }

    /**
     * Return the 'special port' if the URL is special and not 'file'.
     * Returns 0 otherwise.
     */
    [[nodiscard]] uint16_t get_special_port() const {
      return ada::scheme::get_special_port(type);
    }

    /**
     * Return the scheme type. Note that it is faster to do
     * get_scheme_type() == ada::scheme::type::FILE than to do
     * get_scheme() == "file", since the former is a direct integer comparison,
     * while the other involves a (cheap) string test.
     */
    [[nodiscard]] ada_really_inline  ada::scheme::type get_scheme_type() const noexcept {
      return type;
    }


    /**
     * Get the default port if the url's scheme has one, returns 0 otherwise.
     */
    [[nodiscard]] ada_really_inline uint16_t scheme_default_port() const noexcept {
      return scheme::get_special_port(type);
    }

    /**
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
#if ADA_DEVELOP_MODE
    /** Only for development purposes so we can see where the copies are happening. **/
    url oh_no_we_need_to_copy_url() const {
      url answer;
      answer.non_special_scheme = non_special_scheme;
      answer.type = type;
      answer.username = username;
      answer.password = password;
      answer.host = host;
      answer.port = port;
      answer.path = path;
      answer.query = query;
      answer.fragment = fragment;
      answer.is_valid = is_valid;
      return answer;
    }
#endif

    /**
     * Parse a port (16-bit decimal digit) from the provided input.
     * We assume that the input does not contain spaces or tabs
     * within the ASCII digits.
     * It returns how many bytes were consumed when a number is successfully parsed.
     * @see https://url.spec.whatwg.org/#host-parsing
     */
    ada_really_inline size_t parse_port(std::string_view view) noexcept {
          uint16_t parsed_port{};
          auto r = std::from_chars(view.begin(), view.end(), parsed_port);
          if(r.ec == std::errc::result_out_of_range) {
            is_valid = false;
            return 0;
          }
          port = (r.ec == std::errc() && scheme_default_port() != parsed_port) ?
            std::optional<uint16_t>(parsed_port) : std::nullopt;
          const size_t consumed = size_t(r.ptr - view.begin());
          is_valid &= (consumed == view.size() || view[consumed] == '/' || view[consumed] == '?' || (is_special() && view[consumed] == '\\'));
          return consumed;
    }

    /**
     * Return a string representing the scheme. Note that
     * get_scheme_type() should often be used instead.
     */
    std::string_view get_scheme() const noexcept {
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
     * Take the scheme from another URL.
     */
    void copy_scheme(ada::url&& u) {
      non_special_scheme = u.non_special_scheme;
      type = u.type;
    }

    /**
     * Take the scheme from another URL.
     */
    void copy_scheme(const ada::url& u) {
      non_special_scheme = u.non_special_scheme;
      type = u.type;
    }

    /**
     * Parse the host from the provided input. We assume that
     * the input does not contain spaces or tabs. Control
     * characters and spaces are not trimmed (they should have
     * been removed if needed).
     * Return true on success.
     * @see https://url.spec.whatwg.org/#host-parsing
     */
    ada_really_inline bool parse_host(const std::string_view input);

    /**
     * Parse the path from the provided input.
     * Return true on success. Control characters not
     * trimmed from the ends (they should have
     * been removed if needed).
     * @see https://url.spec.whatwg.org/#host-parsing
     */
    ada_really_inline bool parse_path(const std::string_view input);

    /**
     * Parse the path from the provided input. It should have been
     * 'prepared' (e.g., it cannot contain tabs and spaces). See
     * parse_path.
     *
     * Return true on success.
     * @see https://url.spec.whatwg.org/#host-parsing
     */
    ada_really_inline bool parse_prepared_path(const std::string_view input);

    template <bool has_state_override = false>
    ada_really_inline bool parse_scheme(const std::string_view input);

    /**
     * Returns a string representation of this URL.  (Useful for debugging.)
     */
    std::string to_string();

  private:
    /**
     * Return true on success.
     * @see https://url.spec.whatwg.org/#concept-ipv4-parser
     */
    bool parse_ipv4(std::string_view input);

    /**
     * Return true on success.
     * @see https://url.spec.whatwg.org/#concept-ipv6-parser
     */
    bool parse_ipv6(std::string_view input);

    /**
     * Return true on success.
     * @see https://url.spec.whatwg.org/#concept-opaque-host-parser
     */
    bool parse_opaque_host(std::string_view input) noexcept;


    ada::scheme::type type{ada::scheme::type::NOT_SPECIAL};

    /**
     * A URL’s scheme is an ASCII string that identifies the type of URL and can be used to dispatch a
     * URL for further processing after parsing. It is initially the empty string.
     * We only set non_special_scheme when the scheme is non-special, otherwise we avoid constructing
     * string.
     */
    std::string non_special_scheme{};

  }; // struct url

} // namespace ada

#endif // ADA_URL_H
