#ifndef ADA_CHECKERS_H
#define ADA_CHECKERS_H

#include "common_defs.h"

#include <string_view>

namespace ada::checkers {

  // If we wish to separate definitions and declarations, we can do
  // it with a -inl.h files.


  // Assuming that x is an ASCII letter, this returns the lower case equivalent.
  // More likely to be inlined by the compiler and constexpr.
  constexpr char to_lower(char x) { return (x | 0x20); }
  // Returns true if the character is an ASCII letter. Equivalent to std::isalpha but
  // more likely to be inlined by the compiler. Also, std::isalpha is not constexpr
  // generally.
  constexpr bool is_alpha(char x) { return (to_lower(x) >= 'a') & (to_lower(x) <= 'z'); }

  // Check whether a string starts with 0x or 0X. The function is only
  // safe if input.size() >=2. See has_hex_prefix.
  inline bool has_hex_prefix_unsafe(std::string_view input) {
    // This is actualy efficient code, see has_hex_prefix for the assembly.
    uint32_t value = 1;
    bool is_little_endian = (static_cast<uint8_t>(value) == 1);
    uint16_t word0x{};
    std::memcpy(&word0x, "0x", 2); // we would use bit_cast in C++20 and the function could be constexpr.
    uint16_t two_first_bytes{};
    std::memcpy(&two_first_bytes, input.data(),2);
    if(is_little_endian) { two_first_bytes |= 0x2000; } else { two_first_bytes |= 0x020; }
    return two_first_bytes == word0x;
  }

  // Check whether a string starts with 0x or 0X.
  inline bool has_hex_prefix(std::string_view input) {
    /**
    * This is efficient code to check if a string starts with
    * 0x or 0X.
    *
    * GCC12 compiles the following to (under x64):
    *    
    *    cmp     rdi, 1
    *    jbe     .L1
    *    movzx   eax, WORD PTR [rsi]
    *    or      ah, 32
    *    cmp     ax, 30768
    *    sete    al
    *  .L1:
    *    ret
    *
    *    LLVM 14 does:
    *    
    *    cmp     rdi, 2
    *    jae     .L1
    *    xor     eax, eax
    *    ret
    * .L1:
    *    movzx   eax, word ptr [rsi]
    *    and     eax, 57343
    *    cmp     eax, 22576
    *    sete    al
    *    ret
    *
    */
    return has_hex_prefix_unsafe(input);
  }


  // Check whether x is an ASCII digit. More likely to be inlined than std::isdigit.
  constexpr bool is_digit(char x) { return (x >= '0') & (x <= '9'); }

  // A Windows drive letter is two code points, of which the first is an ASCII alpha
  // and the second is either U+003A (:) or U+007C (|).
  inline bool is_windows_drive_letter(const std::string_view input) noexcept {
    return input.size() >= 2 && (is_alpha(input[0]) & ((input[1] == ':') | (input[1] == '|')));
  }

  // A normalized Windows drive letter is a Windows drive letter of which the second code point is U+003A (:).
  inline bool is_normalized_windows_drive_letter(std::string_view input) noexcept {
    return input.size() >= 2 && (is_alpha(input[0]) & (input[1] == ':'));
  }

  /* too large to be inlined: */
  bool ends_in_a_number(std::string_view input) noexcept;

  ada_really_inline constexpr bool is_ipv4_number_valid(std::string_view::iterator iterator_start, std::string_view::iterator iterator_end) noexcept;

} // namespace ada::checkers

#endif //ADA_CHECKERS_H
