#ifndef ADA_URL_H
#define ADA_URL_H

#include <optional>

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
    char* scheme;

    /**
     * A URL’s username is an ASCII string identifying a username. It is initially the empty string.
     */
    char* username;

    /**
     * A URL’s password is an ASCII string identifying a password. It is initially the empty string.
     */
    char* password;

    /**
     * A URL’s port is either null or a 16-bit unsigned integer that identifies a networking port. It is initially null.
     */
    std::optional<uint16_t> port;

    /**
     * A URL’s path is either an ASCII string or a list of zero or more ASCII strings, usually identifying a location.
     * TODO: Change this to list.
     */
    char* path;

    /**
     * A URL’s query is either null or an ASCII string. It is initially null.
     */
    std::optional<char*> query;

    /**
     * A URL’s fragment is either null or an ASCII string that can be used for further processing on the resource
     * the URL’s other components identify. It is initially null.
     */
    std::optional<char*> fragment;

    /**
     * Used for returning the validity from the result of the URL parser.
     */
    bool is_valid = true;
  };

} // namespace ada

#endif // ADA_URL_H
