/**
 * @file checkers-inl.h
 * @brief Definitions for URL specific checkers used within Ada.
 */
#ifndef ADA_CHECKERS_INL_H
#define ADA_CHECKERS_INL_H

#include <bit>
#include <string_view>
#include "ada/checkers.h"

namespace ada::checkers {

constexpr bool has_hex_prefix_unsafe(std::string_view input) {
  // This is actually efficient code, see has_hex_prefix for the assembly.
  constexpr bool is_little_endian = std::endian::native == std::endian::little;
  constexpr uint16_t word0x = 0x7830;
  uint16_t two_first_bytes =
      static_cast<uint16_t>(input[0]) |
      static_cast<uint16_t>((static_cast<uint16_t>(input[1]) << 8));
  if constexpr (is_little_endian) {
    two_first_bytes |= 0x2000;
  } else {
    two_first_bytes |= 0x020;
  }
  return two_first_bytes == word0x;
}

constexpr bool has_hex_prefix(std::string_view input) {
  return input.size() >= 2 && has_hex_prefix_unsafe(input);
}

constexpr bool is_digit(char x) noexcept { return (x >= '0') & (x <= '9'); }

constexpr char to_lower(char x) noexcept { return (x | 0x20); }

constexpr bool is_alpha(char x) noexcept {
  return (to_lower(x) >= 'a') && (to_lower(x) <= 'z');
}

constexpr bool is_windows_drive_letter(std::string_view input) noexcept {
  return input.size() >= 2 &&
         (is_alpha(input[0]) && ((input[1] == ':') || (input[1] == '|'))) &&
         ((input.size() == 2) || (input[2] == '/' || input[2] == '\\' ||
                                  input[2] == '?' || input[2] == '#'));
}

constexpr bool is_normalized_windows_drive_letter(
    std::string_view input) noexcept {
  return input.size() >= 2 && (is_alpha(input[0]) && (input[1] == ':'));
}

ada_really_inline constexpr uint64_t try_parse_ipv4_fast(
    std::string_view input) noexcept {
  const char* p = input.data();
  const char* const pend = p + input.size();

  uint32_t ipv4 = 0;

  for (int i = 0; i < 4; ++i) {
    if (p == pend) {
      return ipv4_fast_fail;
    }

    uint32_t val;
    char c = *p;
    if (c >= '0' && c <= '9') {
      val = c - '0';
      p++;
    } else {
      return ipv4_fast_fail;
    }

    if (p < pend) {
      c = *p;
      if (c >= '0' && c <= '9') {
        if (val == 0) return ipv4_fast_fail;
        val = val * 10 + (c - '0');
        p++;
        if (p < pend) {
          c = *p;
          if (c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
            p++;
            if (val > 255) return ipv4_fast_fail;
          }
        }
      }
    }

    ipv4 = (ipv4 << 8) | val;

    if (i < 3) {
      if (p == pend || *p != '.') {
        return ipv4_fast_fail;
      }
      p++;
    }
  }

  if (p != pend) {
    if (p == pend - 1 && *p == '.') {
      return ipv4;
    }
    return ipv4_fast_fail;
  }

  return ipv4;
}

}  // namespace ada::checkers

#endif  // ADA_CHECKERS_INL_H
