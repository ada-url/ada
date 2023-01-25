/**
 * @file checkers.h
 * @brief Definitions for URL specific checkers used within Ada.
 */
#ifndef ADA_CHECKERS_H
#define ADA_CHECKERS_H

#include "ada/common_defs.h"

#include <string_view>
#include <cstring>

namespace ada::checkers {

  //
  // More likely to be inlined by the compiler and constexpr.
  /**
   * Assuming that x is an ASCII letter, this function returns the lower case equivalent.
   * @details More likely to be inlined by the compiler and constexpr.
   */
  constexpr char to_lower(char x) noexcept { return (x | 0x20); }

  /**
   * Returns true if the character is an ASCII letter. Equivalent to std::isalpha but
   * more likely to be inlined by the compiler.
   *
   * @attention std::isalpha is not constexpr generally.
   */
  constexpr bool is_alpha(char x) noexcept { return (to_lower(x) >= 'a') && (to_lower(x) <= 'z'); }

  /**
   * Check whether a string starts with 0x or 0X. The function is only
   * safe if input.size() >=2.
   *
   * @see has_hex_prefix
   */
  inline bool has_hex_prefix_unsafe(std::string_view input) {
    // This is actualy efficient code, see has_hex_prefix for the assembly.
    uint32_t value_one = 1;
    bool is_little_endian = (reinterpret_cast<char*>(&value_one)[0] == 1);
    uint16_t word0x{};
    std::memcpy(&word0x, "0x", 2); // we would use bit_cast in C++20 and the function could be constexpr.
    uint16_t two_first_bytes{};
    std::memcpy(&two_first_bytes, input.data(),2);
    if(is_little_endian) { two_first_bytes |= 0x2000; } else { two_first_bytes |= 0x020; }
    return two_first_bytes == word0x;
  }

  /**
   * Check whether a string starts with 0x or 0X.
   */
  inline bool has_hex_prefix(std::string_view input) {
    return input.size() >=2 && has_hex_prefix_unsafe(input);
  }

  /**
   * Check whether x is an ASCII digit. More likely to be inlined than std::isdigit.
   */
  constexpr bool is_digit(char x) noexcept { return (x >= '0') & (x <= '9'); }

  /**
   * @details A string starts with a Windows drive letter if all of the following are true:
   *
   *   - its length is greater than or equal to 2
   *   - its first two code points are a Windows drive letter
   *   - its length is 2 or its third code point is U+002F (/), U+005C (\), U+003F (?), or U+0023 (#).
   *
   * https://url.spec.whatwg.org/#start-with-a-windows-drive-letter
   */
  inline constexpr bool is_windows_drive_letter(std::string_view input) noexcept {
    return input.size() >= 2 && (is_alpha(input[0]) && ((input[1] == ':') || (input[1] == '|')))
      && ((input.size() == 2) || (input[2] == '/' || input[2] == '\\' || input[2] == '?' || input[2] == '#'));
  }

  /**
   * @details A normalized Windows drive letter is a Windows drive letter of which the second code point is U+003A (:).
   */
  inline constexpr bool is_normalized_windows_drive_letter(std::string_view input) noexcept {
    return input.size() >= 2 && (is_alpha(input[0]) && (input[1] == ':'));
  }

  /**
   * @warning Will be removed when Ada supports C++20.
   */
  ada_really_inline constexpr bool begins_with(std::string_view view, std::string_view prefix) {
    // in C++20, you have view.begins_with(prefix)
    return view.size() >= prefix.size() && (view.substr(0, prefix.size()) == prefix);
  }

  /**
   * Returns true if an input is an ipv4 address.
   */
  ada_really_inline ada_constexpr bool is_ipv4(std::string_view view) noexcept;

  /**
   * Returns a bitset. If the first bit is set, then at least one character needs
   * percent encoding. If the second bit is set, a \\ is found. If the third bit is set
   * then we have a dot. If the fourth bit is set, then we have a percent character.
   */
  ada_really_inline constexpr uint8_t path_signature(std::string_view input) noexcept;

} // namespace ada::checkers

#endif //ADA_CHECKERS_H
