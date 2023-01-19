#include <memory>
#include <string>
#include <string_view>

namespace ada::puny {

bool from_unicode_letters(uint32_t &code_point) noexcept {
  // https://en.wikipedia.org/wiki/Halfwidth_and_Fullwidth_Forms_(Unicode_block)
  if (code_point >= 0xFF01 && code_point <= 0xFF5E) {
    code_point -= 65248;
    return true;
  }
  // Math:
  if (code_point >= 0x1D400 && code_point <= 0x1D6A3) {
    // https://en.wikipedia.org/wiki/Mathematical_operators_and_symbols_in_Unicode#Mathematical_Alphanumeric_Symbols_block
    code_point = (code_point - 0x1d400) % 26 + 0x61;
    return true;
  }
  return false;
}

bool is_ignorable(uint32_t code_point) noexcept {
  return code_point == 0x00AD || code_point == 0x034F || code_point == 0x061C ||
         (0x115F <= code_point && code_point <= 0x1160) ||
         (0x17B4 <= code_point && code_point <= 0x17B5) ||
         (0x180B <= code_point && code_point <= 0x180D) ||
         code_point == 0x180E || code_point == 0x200B ||
         (0x202A <= code_point && code_point <= 0x202E) ||
         (0x2060 <= code_point && code_point <= 0x2064) ||
         code_point == 0x2065 ||
         (0x2066 <= code_point && code_point <= 0x206F) ||
         code_point == 0x3164 ||
         (0xFE00 <= code_point && code_point <= 0xFE0F) ||
         code_point == 0xFEFF || code_point == 0xFFA0 ||
         (0xFFF0 <= code_point && code_point <= 0xFFF8) ||
         (0x1BCA0 <= code_point && code_point <= 0x1BCA3) ||
         (0x1D173 <= code_point && code_point <= 0x1D17A) ||
         code_point == 0xE0000 || code_point == 0xE0001 ||
         (0xE0002 <= code_point && code_point <= 0xE001F) ||
         (0xE0020 <= code_point && code_point <= 0xE007F) ||
         (0xE0080 <= code_point && code_point <= 0xE00FF) ||
         (0xE0100 <= code_point && code_point <= 0xE01EF) ||
         (0xE01F0 <= code_point && code_point <= 0xE0FFF);
}

bool is_disallowed(uint32_t code_point) noexcept {
  // See RFC 5892 for complete list. (It is very long.)
  // TODO: complete
  return (code_point == 0x3000) || (code_point == 0xFDD0) ||
         (code_point == 0xFFFD) || (code_point == 0xFFFF) ||
         (code_point >= 0x3200 && code_point <= 0x321E) ||
         (code_point >= 0x3220 && code_point <= 0x32FE);
}

uint32_t adapt(uint32_t delta, uint32_t n_points, bool is_first) {
  delta /= is_first ? 700 : 2;
  delta += delta / n_points;

  uint32_t s = 36 - 1;
  uint32_t t = (s * 26) / 2;

  uint32_t k = 0;
  for (; delta > t; k += 36) {
    delta /= s;
  }

  uint32_t a = (36 - 1 + 1) * delta;
  uint32_t b = (delta + 38);

  return k + (a / b);
}

// Converts an UTF-8 input into punycode.
//
// This function is non-allocating and it does not throw.
//
// Parameters:
//
// 'input' should be made of 'input_length' bytes representing a valid UTF-8
// sequence.
//
std::optional<std::string> utf8_to_punycode(const char *input,
                                            size_t input_length) {
  std::string out;

  unsigned char *char_pointer = (unsigned char *)input;
  unsigned char *const end_char_pointer = char_pointer + input_length;

  std::unique_ptr<uint32_t[]> all_buffer_mem(new uint32_t[input_length]);
  uint32_t *all_buffer = all_buffer_mem.get();
  uint32_t *all{all_buffer};

  std::unique_ptr<uint32_t[]> non_basic_buffer_mem(new uint32_t[input_length]);

  uint32_t *non_basic_buffer = non_basic_buffer_mem.get();
  uint32_t *non_basic{non_basic_buffer};
  out += "xn--";

  while (char_pointer < end_char_pointer) {
    unsigned char c = *char_pointer;
    if (c >= 0b10000000) {
      size_t lookahead = size_t(char_pointer - end_char_pointer);
      uint32_t code_point;
      uint32_t leading_byte = c;

      if ((leading_byte & 0b11100000) == 0b11000000) {
        // We have a two-byte UTF-8
        if (lookahead < 2) {
          return out;
        }

        if ((char_pointer[1] & 0b11000000) != 0b10000000) {
          return std::nullopt;
        }
        // range check
        code_point =
            (leading_byte & 0b00011111) << 6 | (char_pointer[1] & 0b00111111);
        if (code_point < 0x80 || 0x7ff < code_point) {
          return std::nullopt;
        }
        char_pointer += 2;
      } else if ((leading_byte & 0b11110000) == 0b11100000) {
        // We have a three-byte UTF-8
        if (lookahead < 3) {
          return std::nullopt;
        }
        if ((char_pointer[1] & 0b11000000) != 0b10000000) {
          return std::nullopt;
        }
        if ((char_pointer[2] & 0b11000000) != 0b10000000) {
          return std::nullopt;
        }
        // range check
        code_point = (leading_byte & 0b00001111) << 12 |
                     (char_pointer[1] & 0b00111111) << 6 |
                     (char_pointer[2] & 0b00111111);
        if (code_point < 0x800 || 0xffff < code_point ||
            (0xd7ff < code_point && code_point < 0xe000)) {
          return std::nullopt;
        }
        char_pointer += 3;
      } else if ((leading_byte & 0b11111000) == 0b11110000) { // 0b11110000
        // we have a 4-byte UTF-8 word.
        if (lookahead < 4) {
          return std::nullopt;
        }

        if ((char_pointer[1] & 0b11000000) != 0b10000000) {
          return std::nullopt;
        }
        if ((char_pointer[2] & 0b11000000) != 0b10000000) {
          return std::nullopt;
        }
        if ((char_pointer[3] & 0b11000000) != 0b10000000) {
          return std::nullopt;
        }

        // range check
        code_point = (leading_byte & 0b00000111) << 18 |
                     (char_pointer[1] & 0b00111111) << 12 |
                     (char_pointer[2] & 0b00111111) << 6 |
                     (char_pointer[3] & 0b00111111);
        if (code_point <= 0xffff || 0x10ffff < code_point) {
          return std::nullopt;
        }
        char_pointer += 4;
      } else {
        // continuation byte
        return std::nullopt;
      }
      if (is_ignorable(code_point)) {
        continue;
      }
      if (is_disallowed(code_point)) {
        return std::nullopt;
      }
      if (from_unicode_letters(code_point)) {
        // ASCII
        c = uint8_t(code_point);
        out.push_back(uint8_t((c | 0x20) - 0x61) <= 25 ? (c | 0x20) : c);
      } else {
        *non_basic++ = code_point;
      }
      *all++ = code_point;

      continue;
    }
    // ASCII !!!

    if (ada::unicode::is_forbidden_domain_code_point(c)) {
      return std::nullopt;
    }
    out.push_back(uint8_t((c | 0x20) - 0x61) <= 25 ? (c | 0x20) : c);
    *all++ = c;
    char_pointer++;
    continue;
  }
  uint32_t number_of_chars(uint32_t(all - all_buffer));
  uint32_t basic_count = uint32_t(out.size() - 4);

  if (non_basic == non_basic_buffer) { // pure ASCII
    return out.substr(4);
  }

  if (basic_count > 0) {
    out.push_back('-');
  }
  uint32_t n = 128;
  uint32_t bias = 72;
  uint32_t delta = 0;

  auto sort_unique_values = [](uint32_t array[], size_t size) {
    size_t duplicates = 0;
    for (size_t k = 1; k < size; k++) {
      size_t z = k - duplicates;
      uint32_t key = array[k];
      for (; (z >= 1) && (array[z - 1] >= key); z--) {
      }
      if (z == k) {
        // nothing to do!
      } else if ((array[z] > key)) {
        std::memmove(array + z + 1, array + z,
                     (k - duplicates - z) * sizeof(uint32_t));
        array[z] = key;
      } else if (array[z] == key) {
        duplicates++;
      } else {
        array[z] = key;
      }
    }
  };

  sort_unique_values(non_basic_buffer, non_basic - non_basic_buffer);
  non_basic = non_basic_buffer;

  for (uint32_t processed = basic_count; processed < number_of_chars;
       ++n, ++delta) {
    uint32_t non_ascii_code_point = *non_basic++;
    delta += (non_ascii_code_point - n) * (processed + 1);
    n = non_ascii_code_point;
    for (size_t i = 0; i < number_of_chars; i++) {
      uint32_t c = all_buffer[i];
      if (c < n && (++delta == 0)) { // overflow
        return std::nullopt;
      }
      if (c == n) {
        for (uint32_t q = delta, k = 36;; k += 36) {
          uint32_t t = k <= bias ? 1 : (k >= bias + 26 ? 26 : k - bias);
          if (q < t) {
            out.push_back(uint8_t(q < 26 ? q + 97 : q + 22));
            break;
          }
          uint32_t char_value = t + (q - t) % (36 - t); // unfortunate division
          out.push_back(uint8_t(char_value < 26 ? char_value + 97 : char_value + 22));

          q = (q - t) / (36 - t);
        }

        bias = adapt(delta, processed + 1, basic_count == processed);
        delta = 0;
        processed++;
      }
    }
  }

  return out;
}

// This function merely verifies that a punycode is valid.
// Important: we do not bother decoding to a buffer.
bool verify_punycode(std::string_view input) {
  // So we ignore the first 'xn--'
  input.remove_prefix(4);
  if (input.empty()) {
    return false;
  }
  auto loc = input.rfind('-');
  uint32_t count = 0;
  if (loc != std::string_view::npos) {
    for(uint8_t c : input.substr(0, loc)) {
      if ((c >= 128) || ada::unicode::is_forbidden_domain_code_point(c)) {
        return false;
      }
    }
    count = uint32_t(loc);
    input.remove_prefix(loc + 1);
  }
  uint32_t n = 128;
  int i = 0;
  int bias = 72;
  for (auto iterator = input.begin(); iterator != input.end();) {
    int start_i = i;
    int w = 1;
    for (int k = 36;; k += 36) {
      if (iterator == input.end()) {
        return false;
      }
      char code_point = *iterator++;
      int digit = ((code_point <= 'z') && (code_point >= 'a'))
                      ? code_point - 'a'
                      : (((code_point <= '0') && (code_point >= '0'))
                             ? code_point - '0' + 26
                             : -1);
      if (digit < 0) {
        return false;
      }
      i = i + digit * w;
      int t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) {
        break;
      }
      w = w * (36 - t);
    }
    bias = adapt(i - start_i, count + 1, start_i == 0);
    n = n + i / (count + 1);
    i = i % (count + 1);
    if ((n < 0x80) || is_disallowed(n)) {
      return false;
    }

    count++;
    i++;
  }

  return true;
}

// We return the empty string on error.
std::optional<std::string> convert_domain_to_puny(std::string_view input, bool be_strict) {
  std::string out;
  (void)be_strict; // currently ignored.
  // We seem to be allowing an infinite domain size and an infinite number of
  // of labels. This is not correct. A domain is limited to 255 characters
  // and labels cannot exceed 64 characters. However, wpt_tests seems to want
  // to allow more general cases?
  // Though wpt_tests does not want limits, let us put one anyhow. If someone
  // has a domain with over 1MB, we refuse to work on it (safety!).
  if(input.size() > 1'000'000) { return std::nullopt; }
  while (!input.empty()) {
    size_t loc_dot = input.find('.');
    size_t loc_full_stop = input.find("\u3002"); // complete as needed
    size_t loc = std::min(loc_dot, loc_full_stop);
    size_t utf8_sep_size = loc == loc_dot ? 1 : 3;
    bool is_last_label = (loc == std::string_view::npos);
    size_t label_size = is_last_label ? input.size() : loc;
    size_t label_size_with_dot =
        is_last_label ? input.size() : loc + utf8_sep_size;
    std::string_view label_view =
        input.substr(0, label_size); // does not contain the dot.
    if(label_view.empty()) {
        // nothing to do.
    // next check is not as expensive as it looks:
    } else if (ada::checkers::begins_with(label_view, "xn--") ||
        ada::checkers::begins_with(label_view, "XN--") ||
        ada::checkers::begins_with(label_view, "Xn--") ||
        ada::checkers::begins_with(label_view, "xN--")) {
      // It is already punycode, we just validate it!
      if (!verify_punycode(label_view)) {
        return std::nullopt;
      }
      out += label_view;
    } else {
      // It is not punycode, we have to do the hard work.
      // This could be made faster by not creating a new temporary string.
      std::optional<std::string> label_string =
          utf8_to_punycode(label_view.data(), label_view.size());

      if (!label_string.has_value()) {
        return std::nullopt;
      }
      if (label_string.value().empty()) {
        return std::nullopt;
      }

      out += label_string.value();
    }
    if (!is_last_label) {
      out.push_back('.');
    }
    input.remove_prefix(label_size_with_dot);
  }
  return out;
}

} // namespace ada::puny
