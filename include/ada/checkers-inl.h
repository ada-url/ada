/**
 * @file checkers-inl.h
 * @brief Definitions for URL specific checkers used within Ada.
 */
#ifndef ADA_CHECKERS_INL_H
#define ADA_CHECKERS_INL_H

#include "ada/common_defs.h"

#include <algorithm>
#include <string_view>
#include <cstring>

namespace ada::checkers {

inline bool has_hex_prefix_unsafe(std::string_view input) {
  // This is actually efficient code, see has_hex_prefix for the assembly.
  uint32_t value_one = 1;
  bool is_little_endian = (reinterpret_cast<char*>(&value_one)[0] == 1);
  uint16_t word0x{};
  std::memcpy(&word0x, "0x", 2);  // we would use bit_cast in C++20 and the
                                  // function could be constexpr.
  uint16_t two_first_bytes{};
  std::memcpy(&two_first_bytes, input.data(), 2);
  if (is_little_endian) {
    two_first_bytes |= 0x2000;
  } else {
    two_first_bytes |= 0x020;
  }
  return two_first_bytes == word0x;
}

inline bool has_hex_prefix(std::string_view input) {
  return input.size() >= 2 && has_hex_prefix_unsafe(input);
}

constexpr bool is_digit(char x) noexcept { return (x >= '0') & (x <= '9'); }

constexpr char to_lower(char x) noexcept { return (x | 0x20); }

constexpr bool is_alpha(char x) noexcept {
  return (to_lower(x) >= 'a') && (to_lower(x) <= 'z');
}

inline constexpr bool is_windows_drive_letter(std::string_view input) noexcept {
  return input.size() >= 2 &&
         (is_alpha(input[0]) && ((input[1] == ':') || (input[1] == '|'))) &&
         ((input.size() == 2) || (input[2] == '/' || input[2] == '\\' ||
                                  input[2] == '?' || input[2] == '#'));
}

inline constexpr bool is_normalized_windows_drive_letter(
    std::string_view input) noexcept {
  return input.size() >= 2 && (is_alpha(input[0]) && (input[1] == ':'));
}

ada_really_inline bool begins_with(std::string_view view,
                                   std::string_view prefix) {
  // in C++20, you have view.begins_with(prefix)
  // std::equal is constexpr in C++20
  return view.size() >= prefix.size() &&
         std::equal(prefix.begin(), prefix.end(), view.begin());
}

}  // namespace ada::checkers

#endif  // ADA_CHECKERS_INL_H
