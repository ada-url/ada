#pragma once

#include <unordered_map>
#include <string_view>
#include <optional>

namespace ada::scheme {

  static const std::unordered_map<std::string_view , std::optional<uint16_t>> SPECIAL_SCHEME {
    { "ftp", 21 },
    { "file", NULL },
    { "http", 80 },
    { "https", 443 },
    { "ws", 80 },
    { "wss", 443 },
  };

  /**
   * A special scheme is an ASCII string that is listed in the first column of the following table.
   * The default port for a special scheme is listed in the second column on the same row.
   * The default port for any other ASCII string is null.
   *
   * @see https://url.spec.whatwg.org/#url-miscellaneous
   * @param scheme
   * @return If scheme is a special scheme
   */
  bool is_special(std::string_view scheme) {
    return SPECIAL_SCHEME.find(scheme) != SPECIAL_SCHEME.end();
  }

} // namespace ada::scheme
