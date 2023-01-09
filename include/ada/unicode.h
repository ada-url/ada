#ifndef ADA_UNICODE_H
#define ADA_UNICODE_H

#include "common_defs.h"
#include <cstring>

namespace ada::unicode {

  ada_really_inline constexpr bool is_forbidden_host_code_point(const char c) noexcept;
  ada_really_inline constexpr bool is_forbidden_domain_code_point(const char c) noexcept;
  ada_really_inline constexpr bool is_ascii_hex_digit(const char c) noexcept;
  ada_really_inline constexpr bool is_c0_control_or_space(const char c) noexcept;
  ada_really_inline constexpr bool is_ascii_tab_or_newline(const char c) noexcept;
  ada_really_inline constexpr bool is_double_dot_path_segment(const std::string_view input) noexcept;
  ada_really_inline bool is_single_dot_path_segment(const std::string_view input) noexcept;

  unsigned constexpr convert_hex_to_binary(char c) noexcept;

  std::string percent_decode(const std::string_view input) noexcept;
  std::string percent_encode(const std::string_view input, const uint8_t character_set[]) noexcept;

} // namespace ada::unicode

#endif // ADA_UNICODE_H
