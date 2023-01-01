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
    uint64_t inputu = helpers::string_to_uint64(scheme);
    uint64_t https = helpers::string_to_uint64("https\0\0\0");
    uint64_t http = helpers::string_to_uint64("http\0\0\0\0");
    uint64_t file = helpers::string_to_uint64("file\0\0\0\0");
    uint64_t ftp = helpers::string_to_uint64("ftp\0\0\0\0\0");
    uint64_t wss = helpers::string_to_uint64("wss\0\0\0\0\0");
    uint64_t ws = helpers::string_to_uint64("ws\0\0\0\0\0\0");
    if((inputu == https) | (inputu == http)) {
      return true;
    }
    return ((inputu == file) | (inputu == ftp)
            | (inputu == wss) | (inputu == ws));
  }

} // namespace ada::scheme
