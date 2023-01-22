#include "ada.h"
#include <algorithm>

namespace ada::checkers {

  ada_really_inline ada_constexpr bool is_ipv4(std::string_view view) noexcept {
    size_t last_dot = view.rfind('.');
    if (last_dot == view.size() - 1) {
      view.remove_suffix(1);
      last_dot = view.rfind('.');
    }
    std::string_view number = (last_dot == std::string_view::npos) ? view : view.substr(last_dot + 1);
    if (number.empty()) { return false; }
    /** Optimization opportunity: we have basically identified the last number of the
        ipv4 if we return true here. We might as well parse it and have at least one
        number parsed when we get to parse_ipv4. */
    if (std::all_of(number.begin(), number.end(), ada::checkers::is_digit)) { return true; }
    return (checkers::has_hex_prefix(number) &&
            std::all_of(number.begin() + 2, number.end(), ada::unicode::is_lowercase_hex));
  }


  // for use with path_signature
  static constexpr uint8_t path_signature_table[256] = {
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  ada_really_inline constexpr uint8_t
  path_signature(std::string_view input) noexcept {

    /**
    * We need percent encoding for code points 32 or less, 127 and more, as well
    * as 34 ("), 35 (#), 60 (<), 62 (>), 63 (?), 96 (`), 123 ({), 125 (}). We set
    * those to '1' in the next array.
    * The character '\' is set to 2. The character '.' is set to 4.
    * The character '%' is set to 8.
    */
    size_t i = 0;
    uint8_t accumulator{};
    for (; i + 7 < input.size(); i += 8) {
      accumulator |= uint8_t(path_signature_table[uint8_t(input[i])] |
                             path_signature_table[uint8_t(input[i + 1])] |
                             path_signature_table[uint8_t(input[i + 2])] |
                             path_signature_table[uint8_t(input[i + 3])] |
                             path_signature_table[uint8_t(input[i + 4])] |
                             path_signature_table[uint8_t(input[i + 5])] |
                             path_signature_table[uint8_t(input[i + 6])] |
                             path_signature_table[uint8_t(input[i + 7])]);
    }
    for (; i < input.size(); i++) {
      accumulator |= path_signature_table[uint8_t(input[i])];
    }
    return accumulator;
  }

} // namespace ada::checkers
