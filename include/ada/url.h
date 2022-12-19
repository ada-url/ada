#ifndef ADA_URL_H
#define ADA_URL_H

#include "scheme.cpp"

#include <optional>
#include <string_view>

namespace ada {

  /**
   * A URL is a struct that represents a universal identifier.
   * To disambiguate from a valid URL string it can also be referred to as a URL record.
   *
   * @see https://url.spec.whatwg.org/#url-representation
   */
  struct URL {
    /**
     * A URL’s scheme is an ASCII string that identifies the type of URL and can be used to dispatch a
     * URL for further processing after parsing. It is initially the empty string.
     */
    std::string_view scheme;

    /**
     * A URL’s username is an ASCII string identifying a username. It is initially the empty string.
     */
    std::string_view username;

    /**
     * A URL’s password is an ASCII string identifying a password. It is initially the empty string.
     */
    std::string_view password;

    /**
     * A URL’s host is null or a host. It is initially null.
     */
    std::optional<std::string_view> host;

    /**
     * A URL’s port is either null or a 16-bit unsigned integer that identifies a networking port. It is initially null.
     */
    std::optional<uint16_t> port;

    /**
     * A URL’s path is either an ASCII string or a list of zero or more ASCII strings, usually identifying a location.
     * TODO: Change this to list.
     */
    std::string_view path;

    /**
     * A URL’s query is either null or an ASCII string. It is initially null.
     */
    std::optional<std::string_view> query;

    /**
     * A URL’s fragment is either null or an ASCII string that can be used for further processing on the resource
     * the URL’s other components identify. It is initially null.
     */
    std::optional<std::string_view> fragment;

    /**
     * Used for returning the validity from the result of the URL parser.
     */
    bool is_valid = true;

    /**
     * A validation error indicates a mismatch between input and valid input.
     * User agents, especially conformance checkers, are encouraged to report them somewhere.
     */
    bool has_validation_error = false;

    /**
     * A URL includes credentials if its username or password is not the empty string.
     * @return
     */
    bool includes_credentials() const {
      return !username.empty() || !password.empty();
    }

    /**
     * A URL is special if its scheme is a special scheme. A URL is not special if its scheme is not a special scheme.
     * @return
     */
    bool is_special() const {
      return ada::scheme::is_special(scheme);
    }
  };

} // namespace ada

#endif // ADA_URL_H
