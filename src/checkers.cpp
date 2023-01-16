#include "ada.h"
#include <algorithm>

namespace ada::checkers {

  ada_really_inline constexpr bool is_ipv4(std::string_view view) noexcept {
    size_t last_dot = view.rfind('.');
    if(last_dot == view.size() - 1) {
      view.remove_suffix(1);
      last_dot = view.rfind('.');
    }
    std::string_view number = (last_dot == std::string_view::npos) ? view : view.substr(last_dot+1);
    if(number.empty()) { return false; }
    /** Optimization opportunity: we have basically identified the last number of the
        ipv4 if we return true here. We might as well parse it and have at least one
        number parsed when we get to parse_ipv4. */
    if(std::all_of(number.begin(), number.end(), ada::checkers::is_digit)) { return true; }
    return (checkers::has_hex_prefix(number) && std::all_of(number.begin()+2, number.end(), ada::unicode::is_lowercase_hex));
  }

} // namespace ada::checkers
