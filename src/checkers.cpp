#include "ada.h"

#include <algorithm>

namespace ada::checkers {

  ada_really_inline constexpr bool is_next_equals(const std::string_view::iterator start,
                                              const std::string_view::iterator end,
                                              const char c) {
    return (std::distance(start, end) > 0) && (start[1] == c);
  }

  ada_really_inline constexpr bool is_not_next_equals(const std::string_view::iterator start,
                                              const std::string_view::iterator end,
                                              const char c) {
    return (std::distance(start, end) > 0) && (start[1] != c);
  }

} // namespace ada::checkers
