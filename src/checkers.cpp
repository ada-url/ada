#include "ada/checkers.h"
#include <algorithm>

namespace ada::checkers {

ada_really_inline ada_constexpr bool is_ipv4(std::string_view view) noexcept {
  size_t last_dot = view.rfind('.');
  if (last_dot == view.size() - 1) {
    view.remove_suffix(1);
    last_dot = view.rfind('.');
  }
  std::string_view number =
      (last_dot == std::string_view::npos) ? view : view.substr(last_dot + 1);
  if (number.empty()) {
    return false;
  }
  /** Optimization opportunity: we have basically identified the last number of
     the ipv4 if we return true here. We might as well parse it and have at
     least one number parsed when we get to parse_ipv4. */
  if (std::all_of(number.begin(), number.end(), ada::checkers::is_digit)) {
    return true;
  }
  return (checkers::has_hex_prefix(number) &&
          std::all_of(number.begin() + 2, number.end(),
                      ada::unicode::is_lowercase_hex));
}

// for use with path_signature, we include all characters that need percent
// encoding.
static constexpr uint8_t path_signature_table[256] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
static_assert(path_signature_table[uint8_t('?')] == 1);
static_assert(path_signature_table[uint8_t('`')] == 1);
static_assert(path_signature_table[uint8_t('{')] == 1);
static_assert(path_signature_table[uint8_t('}')] == 1);
//
static_assert(path_signature_table[uint8_t(' ')] == 1);
static_assert(path_signature_table[uint8_t('?')] == 1);
static_assert(path_signature_table[uint8_t('"')] == 1);
static_assert(path_signature_table[uint8_t('#')] == 1);
static_assert(path_signature_table[uint8_t('<')] == 1);
static_assert(path_signature_table[uint8_t('>')] == 1);
static_assert(path_signature_table[uint8_t('\\')] == 2);
static_assert(path_signature_table[uint8_t('.')] == 4);
static_assert(path_signature_table[uint8_t('%')] == 8);

//
static_assert(path_signature_table[0] == 1);
static_assert(path_signature_table[31] == 1);
static_assert(path_signature_table[127] == 1);
static_assert(path_signature_table[128] == 1);
static_assert(path_signature_table[255] == 1);

ada_really_inline constexpr uint8_t path_signature(
    std::string_view input) noexcept {
  // The path percent-encode set is the query percent-encode set and U+003F (?),
  // U+0060 (`), U+007B ({), and U+007D (}). The query percent-encode set is the
  // C0 control percent-encode set and U+0020 SPACE, U+0022 ("), U+0023 (#),
  // U+003C (<), and U+003E (>). The C0 control percent-encode set are the C0
  // controls and all code points greater than U+007E (~).
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
    accumulator |= uint8_t(path_signature_table[uint8_t(input[i])]);
  }
  return accumulator;
}

ada_really_inline constexpr bool verify_dns_length(
    std::string_view input) noexcept {
  if (input.back() == '.') {
    if (input.size() > 254) return false;
  } else if (input.size() > 253)
    return false;

  size_t start = 0;
  while (start < input.size()) {
    auto dot_location = input.find('.', start);
    // If not found, it's likely the end of the domain
    if (dot_location == std::string_view::npos) dot_location = input.size();

    auto label_size = dot_location - start;
    if (label_size > 63 || label_size == 0) return false;

    start = dot_location + 1;
  }

  return true;
}
}  // namespace ada::checkers
