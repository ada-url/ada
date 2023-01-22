#ifndef ADA_UNICODE_H
#define ADA_UNICODE_H

#include "common_defs.h"
#include <string>
#include <optional>

namespace ada::unicode {

  // first_percent should be  = plain.find('%')
  bool to_ascii(std::optional<std::string>& out, std::string_view plain, bool be_strict, size_t first_percent);
  ada_really_inline constexpr bool has_tabs_or_newline(std::string_view user_input) noexcept;
  ada_really_inline constexpr bool is_forbidden_host_code_point(const char c) noexcept;
  ada_really_inline constexpr bool is_forbidden_domain_code_point(const char c) noexcept;
  ada_really_inline constexpr bool is_alnum_plus(const char c) noexcept;
  ada_really_inline constexpr bool is_ascii_hex_digit(const char c) noexcept;
  ada_really_inline constexpr bool is_c0_control_or_space(const char c) noexcept;
  ada_really_inline constexpr bool is_ascii_tab_or_newline(const char c) noexcept;
  ada_really_inline ada_constexpr bool is_double_dot_path_segment(const std::string_view input) noexcept;
  ada_really_inline constexpr bool is_single_dot_path_segment(const std::string_view input) noexcept;
  ada_really_inline constexpr bool is_lowercase_hex(const char c) noexcept;

  unsigned constexpr convert_hex_to_binary(char c) noexcept;

  // TODO: these functions would be faster as noexcept maybe, but it could be unsafe since
  // they are allocating.
  // first_percent should be  = plain.find('%')
  std::string percent_decode(const std::string_view input, size_t first_percent);
  std::string percent_encode(const std::string_view input, const uint8_t character_set[]);
  size_t utf16_to_utf8(const char16_t* buf, size_t len, char* utf8_output, encoding_type type);
} // namespace ada::unicode

#endif // ADA_UNICODE_H
