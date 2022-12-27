#ifndef ADA_URL_H
#define ADA_URL_H

#include "common_defs.h"

#include <optional>
#include <string>
#include <string_view>

namespace ada {

  /**
   * A URL’s path is either an ASCII string or a list of zero or more ASCII strings, usually identifying a location.
   * It is initially « ».
   *
   * Note: A special URL’s path is always a list, i.e., it is never opaque.
   *
   * @see https://url.spec.whatwg.org/#concept-url-path
   */
  struct url_path {

    std::optional<std::string_view> string_value{};

    std::vector<std::string_view> list_value{};

    /**
     * A URL has an opaque path if its path is a string.
     */
    [[nodiscard]] bool is_opaque() const {
      return string_value.has_value();
    }
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
    std::optional<std::string_view> host{};

    /**
     * A URL’s port is either null or a 16-bit unsigned integer that identifies a networking port. It is initially null.
     */
    std::optional<uint16_t> port{};

    /**
     * A URL’s path is either an ASCII string or a list of zero or more ASCII strings, usually identifying a location.
     */
    url_path path{};

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
    [[nodiscard]] ada_really_inline bool has_opaque_path() const {
      return path.is_opaque();
    }

    /**
     * @see https://url.spec.whatwg.org/#shorten-a-urls-path
     *
     * This function assumes url does not have an opaque path.
     */
    void shorten_path() {
      // Let path be url’s path.
      // If url’s scheme is "file", path’s size is 1, and path[0] is a normalized Windows drive letter, then return.
      if (scheme == "file" && path.list_value.size() == 1 && checkers::is_normalized_windows_drive_letter(path.list_value[0])) {
        return;
      }

      // Remove path’s last item, if any.
      path.list_value.pop_back();
    }

    [[nodiscard]] std::optional<uint16_t> scheme_default_port() const;
  }; // struct url

} // namespace ada

#endif // ADA_URL_H
