#ifndef ADA_URL_H
#define ADA_URL_H

#include "checkers.h"
#include "common_defs.h"
#include "serializers.h"

#include <optional>
#include <string>
#include <string_view>

namespace ada {

  /**
   * @see https://url.spec.whatwg.org/#host-representation
   */
  enum class host_type {
    BASIC_DOMAIN, // Had to use BASIC_ prefix due to global define in <cmath>
    IPV6_ADDRESS,
    IPV4_ADDRESS,
    OPAQUE_HOST,
  };

  ada_warn_unused std::string to_string(ada::host_type type);

  /**
   * @see https://url.spec.whatwg.org/#host-representation
   */
  struct url_host {

    ada::host_type type{ada::host_type::BASIC_DOMAIN};

    std::string entry{};

    ada_warn_unused std::string to_string();
  };

  /**
   * A URL is a struct that represents a universal identifier.
   * To disambiguate from a valid URL string it can also be referred to as a URL record.
   *
   * @see https://url.spec.whatwg.org/#url-representation
   */
  struct url {
    /**
     * A URL’s scheme is an ASCII string that identifies the type of URL and can be used to dispatch a
     * URL for further processing after parsing. It is initially the empty string.
     */
    std::string scheme{};

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
    std::optional<ada::url_host> host{};

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
    bool is_valid = true;

    /**
     * A URL includes credentials if its username or password is not the empty string.
     */
    [[nodiscard]] ada_really_inline bool includes_credentials() const {
      return !username.empty() || !password.empty();
    }

    /**
     * A URL is special if its scheme is a special scheme. A URL is not special if its scheme is not a special scheme.
     */
    [[nodiscard]] ada_really_inline bool is_special() const;

    /**
     * A URL has an opaque path if its path is a string.
     */
    bool has_opaque_path{false};

    [[nodiscard]] std::optional<uint16_t> scheme_default_port() const;

    /**
     * A URL cannot have a username/password/port if its host is null or the empty string, or its scheme is "file".
     */
    [[nodiscard]] bool cannot_have_credentials_or_port() const {
      return !host.has_value() || host.value().entry.empty() || scheme == "file";
    }
    /** For development purposes, we want to know when a copy is made. */
    url() = default;
    url(const url &u) = delete; /**TODO: reanable this before the first release. */
    url(url &&u) = default;
    url &operator=(url &&u) = default;
    url &operator=(const url &u) = delete;
    ADA_ATTRIBUTE_NOINLINE ~url() = default;
    /** Only for development purposes so we can see where the copies are happening. **/
    url oh_no_we_need_to_copy_url() const {
      url answer;
      answer.scheme = scheme;
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

    std::string to_string();
  }; // struct url

} // namespace ada

#endif // ADA_URL_H