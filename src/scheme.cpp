#include <unordered_map>
#include <string_view>
#include <optional>

namespace ada::scheme {
  namespace details {
    // for use with is_special and get_special_port
    constexpr std::string_view is_special_list[] = {"http", "", "https",
      "ws", "ftp", "wss", "file", ""};
    // for use with get_special_port
    constexpr uint16_t special_ports[] = {80, 0xFFFF, 443, 80, 21, 443, 0, 0xFFFF};
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
  ADA_ATTRIBUTE_NOINLINE constexpr uint16_t get_special_port(std::string_view scheme) noexcept {
    if(scheme.empty()) { return 0; }
    int hash_value = (2*scheme.size() + (unsigned)(scheme[0])) & 7;
    const std::string_view target = details::is_special_list[hash_value];
    if ((target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1))) {
        return details::special_ports[hash_value];
    } else { return 0; }
  }
} // namespace ada::scheme
