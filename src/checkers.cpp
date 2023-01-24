#include "ada.h"
#include <algorithm>

namespace ada::checkers {

  ada_really_inline ada_constexpr bool is_ipv4(std::string_view view) noexcept {
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

  ada_really_inline constexpr uint8_t path_signature(std::string_view input) noexcept {
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

  ada_really_inline constexpr bool check_domain(std::string_view input) noexcept {
    if(input.size() > 255) {
      return false;
    }

    const char* start = input.data();
    const char* end = start + input.size();

    int dot_count = 0;
    while (start < end) {
        // Find the next dot in the domain
        const char* dot = std::find(start, end, '.');

        // Calculate the size of the current label
        auto size = dot - start;
        if (size > 63 || size == 0) {
            return false;
        }

        ++dot_count;
        start = dot + 1;
    }

    // Number of Labels is greater than 127
    if(dot_count > 127) {
        return false;
    }

    return true;
  }
  
} // namespace ada::checkers
