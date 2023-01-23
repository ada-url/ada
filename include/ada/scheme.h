/**
 * @file scheme.h
 * @brief Definitions for the URL scheme.
 */
#ifndef ADA_SCHEME_H
#define ADA_SCHEME_H

#include "common_defs.h"

#include <array>
#include <optional>
#include <string>



namespace ada::scheme {
  /**
   * Type of the scheme as an enum.
   * Using strings to represent a scheme type is not ideal because
   * checking for types involves string comparisons. It is faster to use
   * a simple integer.
   */
  enum type {
    HTTP = 0,
    NOT_SPECIAL = 1,
    HTTPS = 2,
    WS = 3,
    FTP = 4,
    WSS = 5,
    FILE = 6
  };

  namespace details {
    // for use with is_special and get_special_port
    constexpr std::string_view is_special_list[] = {"http", "", "https",
                                                    "ws", "ftp", "wss", "file", ""};
    // for use with get_special_port
    constexpr uint16_t special_ports[] = {80, 0, 443, 80, 21, 443, 0, 0};
  }

  /**
   * A special scheme is an ASCII string that is listed in the first column of the following table.
   * The default port for a special scheme is listed in the second column on the same row.
   * The default port for any other ASCII string is null.
   *
   * @see https://url.spec.whatwg.org/#url-miscellaneous
   * @param scheme
   * @return If scheme is a special scheme
   */
  ada_really_inline constexpr bool is_special(std::string_view scheme) {
    if(scheme.empty()) { return false; }
    int hash_value = (2*scheme.size() + (unsigned)(scheme[0])) & 7;
    const std::string_view target = details::is_special_list[hash_value];
    return (target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1));
  }

  /**
   * A special scheme is an ASCII string that is listed in the first column of the following table.
   * The default port for a special scheme is listed in the second column on the same row.
   * The default port for any other ASCII string is null.
   *
   * @see https://url.spec.whatwg.org/#url-miscellaneous
   * @param scheme
   * @return The special port
   */
  constexpr uint16_t get_special_port(std::string_view scheme) noexcept {
    if(scheme.empty()) { return 0; }
    int hash_value = (2*scheme.size() + (unsigned)(scheme[0])) & 7;
    const std::string_view target = details::is_special_list[hash_value];
    if ((target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1))) {
      return details::special_ports[hash_value];
    } else { return 0; }
  }

  /**
   * Returns the port number of a special scheme.
   * @see https://url.spec.whatwg.org/#special-scheme
   */
  constexpr uint16_t get_special_port(ada::scheme::type type) noexcept {
    return details::special_ports[int(type)];
  }

  /**
   * Returns the scheme of an input, or NOT_SPECIAL if it's not a special scheme defined by the spec.
   */
  constexpr ada::scheme::type get_scheme_type(std::string_view scheme) noexcept {
    if(scheme.empty()) { return ada::scheme::NOT_SPECIAL; }
    int hash_value = (2*scheme.size() + (unsigned)(scheme[0])) & 7;
    const std::string_view target = details::is_special_list[hash_value];
    if ((target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1))) {
      return ada::scheme::type(hash_value);
    } else { return ada::scheme::NOT_SPECIAL; }
  }

} // namespace ada::serializers

#endif // ADA_SCHEME_H
