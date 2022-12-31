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
  ada_really_inline bool is_special(std::string_view scheme) noexcept {
    uint64_t schemeu = helpers::string_to_uint64(scheme);
    if ((schemeu & 0xffffffffff) == helpers::string_to_uint64("https\0\0\0")) {
      return scheme.size() == 5;
    }
    if ((schemeu & 0xffffffff) == helpers::string_to_uint64("http\0\0\0\0")) {
      return scheme.size() == 4;
    }
    if (uint32_t(schemeu) == helpers::string_to_uint32("file")) {
      return scheme.size() == 4;
    }
    if ((schemeu & 0xffffff) == helpers::string_to_uint32("ftp\0")) {
      return scheme.size() == 3;
    }
    if ((schemeu & 0xffffff) == helpers::string_to_uint32("wss\0")) {
      return scheme.size() == 3;
    }
    if ((schemeu & 0xffff) == helpers::string_to_uint32("ws\0\0")) {
      return scheme.size() == 2;
    }
    return false;
  }

} // namespace ada::scheme
