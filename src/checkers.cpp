#include "ada/checkers.h"
#include <algorithm>

namespace ada::checkers {

ada_really_inline ada_constexpr bool is_ipv4(std::string_view view) noexcept {
  // The string is not empty and does not contain upper case ASCII characters.
  //
  // Optimization. To be considered as a possible ipv4, the string must end
  // with 'x' or a lowercase hex character.
  // Most of the time, this will be false so this simple check will save a lot
  // of effort.
  char last_char = view.back();
  // If the address ends with a dot, we need to prune it (special case).
  if (last_char == '.') {
    view.remove_suffix(1);
    if (view.empty()) {
      return false;
    }
    last_char = view.back();
  }
  bool possible_ipv4 = (last_char >= '0' && last_char <= '9') ||
                       (last_char >= 'a' && last_char <= 'f') ||
                       last_char == 'x';
  if (!possible_ipv4) {
    return false;
  }
  // From the last character, find the last dot.
  size_t last_dot = view.rfind('.');
  if (last_dot != std::string_view::npos) {
    // We have at least one dot.
    view = view.substr(last_dot + 1);
  }
  /** Optimization opportunity: we have basically identified the last number of
     the ipv4 if we return true here. We might as well parse it and have at
     least one number parsed when we get to parse_ipv4. */
  if (std::all_of(view.begin(), view.end(), ada::checkers::is_digit)) {
    return true;
  }
  // It could be hex (0x), but not if there is a single character.
  if (view.size() == 1) {
    return false;
  }
  // It must start with 0x.
  if (!std::equal(view.begin(), view.begin() + 2, "0x")) {
    return false;
  }
  // We must allow "0x".
  if (view.size() == 2) {
    return true;
  }
  // We have 0x followed by some characters, we need to check that they are
  // hexadecimals.
  return std::all_of(view.begin() + 2, view.end(),
                     ada::unicode::is_lowercase_hex);
}

// for use with path_signature, we include all characters that need percent
// encoding.
static constexpr std::array<uint8_t, 256> path_signature_table =
    []() constexpr {
  std::array<uint8_t, 256> result{};
  for (size_t i = 0; i < 256; i++) {
    if (i <= 0x20 || i == 0x22 || i == 0x23 || i == 0x3c || i == 0x3e ||
        i == 0x3f || i == 0x60 || i == 0x7b || i == 0x7b || i == 0x7d ||
        i > 0x7e) {
      result[i] = 1;
    } else if (i == 0x25) {
      result[i] = 8;
    } else if (i == 0x2e) {
      result[i] = 4;
    } else if (i == 0x5c) {
      result[i] = 2;
    } else {
      result[i] = 0;
    }
  }
  return result;
}
();

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
