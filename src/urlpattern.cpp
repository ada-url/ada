#include "ada/unicode.h"
#include "ada/urlpattern.h"
#include <forward_list>

namespace ada {

ada_really_inline bool is_valid_name_code_point(const char32_t& c,
                                                bool is_first) noexcept {
  return is_first ? unicode::is_valid_identifier_start(c)
                  : unicode::is_valid_identifier_part(c);
}

ada_really_inline bool is_ascii(char32_t c) { return c < 0x80; }

enum class TOKEN_TYPE {
  OPEN,
  CLOSE,
  REGEXP,
  NAME,
  CHAR,
  ESCAPED_CHAR,
  OTHER_MODIFIER,
  ASTERISK,
  END,
  INVALID_CHAR
};

enum class POLICY { STRICT, LENIENT };

struct TOKEN {
  TOKEN_TYPE token;
  size_t start;
  size_t end;
};

ada_really_inline std::forward_list<TOKEN> tokenize(std::string_view input,
                                                    POLICY policy) {
  // Need to deal with Unicode points, so convert to std::u32string_view
  std::forward_list<TOKEN> tokens{};
  size_t input_size = input.size();

  // TODO: convert input to utf32
  const auto error_or_invalid = [&](const std::string_view msg, size_t start,
                                    size_t end) {
    if (policy != POLICY::LENIENT) {
      throw std::invalid_argument(std::string(msg));
    }
    tokens.push_front({TOKEN_TYPE::INVALID_CHAR, start, end});
  };

  size_t index = 0;
  while (index < input_size) {
    switch (input[index]) {
      case '*': {
        tokens.push_front({TOKEN_TYPE::ASTERISK, index, index});
        ++index;
        break;
      }
      case '+':
      case '?': {
        tokens.push_front({TOKEN_TYPE::OTHER_MODIFIER, index, index});
        ++index;
        break;
      }
      case '\\': {
        if (index == input_size - 1) {
          error_or_invalid("should scape something", index, index);
          ++index;
        }

        tokens.push_front({TOKEN_TYPE::ESCAPED_CHAR, ++index, index});
        break;
      }
      case '{': {
        tokens.push_front({TOKEN_TYPE::OPEN, index, index});
        ++index;
        break;
      }
      case '}': {
        tokens.push_front({TOKEN_TYPE::CLOSE, index, index});
        ++index;
        break;
      }
      case ':': {
        // If valid code point is false, break.
        // Set name position to tokenizer’s next index.
        size_t start, end;
        start = index + 1;
        end = start;

        if ((end < input_size) &&
            is_valid_name_code_point(input[end], /*is_first=*/true)) {
          ++end;
          while (end < input_size &&
                 is_valid_name_code_point(input[end], /*is_first=*/false)) {
            ++end;
          }
        } else {
          // First character is not a valid name code point, so there's a
          // missing parameter name.
          error_or_invalid("missing parameter name", start, end);
          continue;
        }

        tokens.push_front({TOKEN_TYPE::NAME, start, end});

        index = end;
        break;
      }
      case '(': {
        size_t regexp_start, regexp, depth;
        regexp_start = index + 1;
        regexp = regexp_start;
        depth = 1;

        bool error = false;
        while (regexp < input_size) {
          // If regexp position equals regexp start and tokenizer’s code point
          // is U+003F (?):
          // Run process a tokenizing error given tokenizer, regexp start, and
          // tokenizer’s index.
          // Set error to true.
          if (!is_ascii(input[regexp])) {
            error_or_invalid("invalid char for regex", regexp, regexp);

            error = true;
            break;
          }
          if (input[regexp] == '?' && (regexp == regexp_start)) {
            error_or_invalid("malformed regex", regexp, regexp);

            error = true;
            break;
          }
          if (input[regexp] == '\\') {
            if (regexp == input_size - 1) {
              error_or_invalid("malformed regex", regexp, regexp);

              error = true;
              break;
            }
            ++regexp;
            if (!is_ascii(input[regexp])) {
              error_or_invalid("invalid char for regex", regexp, regexp);

              error = true;
              break;
            }
            ++regexp;
            continue;
          }

          if (input[regexp] == ')') {
            --depth;
            if (depth == 0) {
              ++regexp;
            }
          } else if (input[regexp] == '(') {
            ++depth;
            if (regexp == input_size - 1) {
              error_or_invalid("malformed regex", regexp, regexp);

              error = true;
              break;
            }
            if (input[regexp + 1] != '?') {
              error_or_invalid("malformed regex", regexp, regexp);

              error = true;
              break;
            }
            ++regexp;
          }

          ++regexp;

          if (error) continue;

          if (depth) {
            error_or_invalid("malformed regex", regexp, regexp);
            break;
          }

          if ((regexp - regexp_start) == 0) {
            error_or_invalid("malformed regex", regexp, regexp);
          }

          tokens.push_front({TOKEN_TYPE::REGEXP, regexp_start, regexp});
          index = regexp;
        }
      }
    }

    tokens.push_front({TOKEN_TYPE::CHAR, index, index});
  }

  tokens.push_front({TOKEN_TYPE::END, index, index});
  return tokens;
}

}  // namespace ada
