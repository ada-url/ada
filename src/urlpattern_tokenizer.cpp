#include "ada/urlpattern_tokenizer.h"
#include "ada/unicode.h"
#include "ada/urlpattern.h"

#include <iostream>
#include <ostream>

namespace ada::urlpattern {

ada_really_inline bool is_valid_name_code_point(const char32_t &c,
                                                bool is_first) noexcept {
  return is_first ? unicode::is_valid_identifier_start(c)
                  : unicode::is_valid_identifier_part(c);
}

ada_really_inline bool is_ascii(char32_t &c) { return c < 0x80; }

// https://wicg.github.io/urlpattern/#seek-and-get-the-next-code-point
ada_really_inline void tokenizer::seek_and_get_next_code_point(size_t &_index) {
  // Set tokenizer’s next index to index.
  next_index = _index;

  // Run get the next code point given tokenizer.
  get_next_code_point();
}

// https://wicg.github.io/urlpattern/#get-the-next-code-point
ada_really_inline void tokenizer::get_next_code_point() {
  // Set tokenizer’s code point to the Unicode code point in tokenizer’s input
  // at the position indicated by tokenizer’s next index.
  code_point = input[next_index];

  // Increment tokenizer’s next index by 1.
  ++next_index;
}

// https://wicg.github.io/urlpattern/#add-a-token
ada_really_inline void tokenizer::add_token(TOKEN_TYPE type, size_t value_start,
                                            size_t value_end) {
  token new_token = token();
  new_token.type = type;
  new_token.value_start = value_start;
  new_token.value_end = value_end;

  token_list.push_back(new_token);
  index = value_end;
}

// https://wicg.github.io/urlpattern/#add-a-token
ada_really_inline void tokenizer::add_token(TOKEN_TYPE type) {
  // 1. Let token be a new token.
  token new_token = token();

  // 2. Set token’s type to type.
  new_token.type = type;

  // 3. Set token’s index to tokenizer’s index.
  // 4. Set token’s value to the code point substring from value position with
  // length value length within tokenizer’s input.
  new_token.value_start = index;
  new_token.value_end = index;

  // 5. Append token to the back of tokenizer’s token list.
  token_list.push_back(new_token);

  // Set tokenizer’s index to next position.
  index = next_index;
}

void tokenizer::process_tokenizing_error(std::string_view msg,
                                         size_t value_start, size_t value_end) {
  if (policy != POLICY::LENIENT) {
    throw std::invalid_argument(std::string(msg));
  }

  add_token(TOKEN_TYPE::INVALID_CHAR, value_start, value_end);
}

std::vector<token> tokenize(std::u32string_view input,
                            ada::urlpattern::POLICY policy) {
  // Let tokenizer be a new tokenizer.
  auto t = tokenizer();

  // Set tokenizer’s input to input.
  t.input = input;

  // Set tokenizer’s policy to policy.
  t.policy = policy;

  // While tokenizer’s index is less than tokenizer’s input's code point length:
  while (t.index < t.input.size()) {
    // Run seek and get the next code point given tokenizer and tokenizer’s
    // index.
    t.seek_and_get_next_code_point(t.index);

    switch (t.code_point) {
      case '*': {
        std::cerr << "'*'" << std::endl;
        // Run add a token with default position and length given tokenizer and
        // "asterisk".
        t.add_token(TOKEN_TYPE::ASTERISK);
        break;
      }
      case '+':
      case '?': {
        std::cerr << "'?''+'" << std::endl;
        t.add_token(TOKEN_TYPE::OTHER_MODIFIER);
        break;
      }
      case '\\': {
        std::cerr << "'\\'" << std::endl;
        // 1. If tokenizer’s index is equal to tokenizer’s input's code point
        // length − 1:
        if (t.index == t.input.size() - 1) {
          // Run process a tokenizing error given tokenizer, tokenizer’s next
          // index, and tokenizer’s index.
          t.process_tokenizing_error("should scape something",
                                     /*value_start*/ t.index,
                                     /*value_end*/ t.next_index);
          continue;
        }
        // 2.Let escaped index be tokenizer’s next index.
        size_t escaped_index = t.next_index;

        // 3. Run get the next code point given tokenizer.
        t.get_next_code_point();

        // Run add a token with default length given tokenizer, "escaped-char",
        // tokenizer’s next index, and escaped index.
        t.add_token(TOKEN_TYPE::ESCAPED_CHAR, escaped_index, escaped_index);
        break;
      }
      case '{': {
        std::cerr << "'{'" << std::endl;
        t.add_token(TOKEN_TYPE::OPEN);
        break;
      }
      case '}': {
        std::cerr << "'}'" << std::endl;
        t.add_token(TOKEN_TYPE::CLOSE);
        break;
      }
      case ':': {
        std::cerr << "':'" << std::endl;
        // 1. Let name position be tokenizer’s next index.
        size_t name_start, name_position;
        name_position = t.next_index;

        // 2. Let name start be name position.
        name_start = name_position;

        // 3. While name position is less than tokenizer’s input's code point
        // length:
        while (name_position < t.input.size()) {
          std::cerr << name_position << std::endl;
          if (t.code_point == U'𐤀') {
            std::cerr << "HELLOOOOOOOO" << std::endl;
          }

          // Run seek and get the next code point given tokenizer and name
          // position.
          t.seek_and_get_next_code_point(name_position);

          // Let first code point be true if name position equals name start and
          // false otherwise.
          bool first_code_point = name_position == name_start;

          // Let valid code point be the result of running is a valid name code
          // point given tokenizer’s code point and first code point.
          // std::cerr << "IS FIRST " << first_code_point << std::endl;
          bool valid_code_point =
              is_valid_name_code_point(t.input[name_position],
                                       /*is_first=*/first_code_point);

          // If valid code point is false break.
          if (!valid_code_point) {
            std::cerr << "NOT VALID CODE POOINT" << t.code_point << std::endl;
            break;
          }

          // Set name position to tokenizer’s next index.
          name_position = t.next_index;
          std::cerr << "final: " << name_position << std::endl;
        }
        std::cerr << "after loop: " << name_position << std::endl;

        // If name position is less than or equal to name start:
        if (name_position <= name_start) {
          std::cerr << "ERROR " << name_position << std::endl;
          t.process_tokenizing_error("missing pattern name", t.index,
                                     name_start);
          break;
        }
        t.add_token(TOKEN_TYPE::NAME, name_start, name_position);
        break;
      }
      case '(': {
        std::cerr << "'('" << std::endl;
        // 1. Let depth be 1.
        size_t depth = 1;

        size_t regexp_start, regexp_position;

        // 2. Let regexp position be tokenizer’s next index.
        regexp_position = t.next_index;

        // 3. Let regexp start be regexp position.
        regexp_start = regexp_position;

        // 4. Let error be false.
        bool error = false;
        while (regexp_position < t.input.size()) {
          // 1. Run seek and get the next code point given tokenizer and regexp
          // position.
          t.seek_and_get_next_code_point(regexp_position);

          // 2. If the result of running is ASCII given tokenizer’s code point
          // is false:
          if (!is_ascii(t.code_point)) {
            // Run process a tokenizing error given tokenizer, regexp start,
            // and tokenizer’s index.
            // Set error to true.
            // Break.
            t.process_tokenizing_error("invalid char for regex", regexp_start,
                                       t.index);

            error = true;
            break;
          }

          // 3. If regexp position equals regexp start and tokenizer’s code
          // point is U+003F (?):
          if (t.code_point == '?' && (regexp_position == regexp_start)) {
            // Run process a tokenizing error given tokenizer, regexp start,
            // and tokenizer’s index.
            // Set error to true.
            // Break.
            t.process_tokenizing_error("malformed regex", regexp_start,
                                       t.index);

            error = true;
            break;
          }

          // 4. If tokenizer’s code point is U+005C (\):
          if (t.code_point == '\\') {
            // 1. If regexp position equals tokenizer’s input's code point
            // length − 1:
            if (regexp_position == t.input.size() - 1) {
              // Run process a tokenizing error given tokenizer, regexp start,
              // and tokenizer’s index.
              // Set error to true.
              // Break.
              t.process_tokenizing_error("malformed regex", regexp_start,
                                         t.index);

              error = true;
              break;
            }

            // 2. Run get the next code point given tokenizer.
            t.get_next_code_point();

            // 3. If the result of running is ASCII given tokenizer’s code point
            // is false
            if (!is_ascii(t.code_point)) {
              t.process_tokenizing_error("invalid char for regex", regexp_start,
                                         t.index);

              error = true;
              break;
            }

            // 4. Set regexp position to tokenizer’s next index.
            regexp_position = t.next_index;
            continue;
          }

          // 5. If tokenizer’s code point is U+0029 ()):
          if (t.code_point == ')') {
            --depth;
            if (depth == 0) {
              // Set regexp position to tokenizer’s next index.
              regexp_position = t.next_index;
              break;
            }
          }
          // 6. Else if tokenizer’s code point is U+0028 (():
          else if (t.code_point == '(') {
            ++depth;
            // 2. If regexp position equals tokenizer’s input's code point
            // length − 1:
            if (regexp_position == t.input.size() - 1) {
              t.process_tokenizing_error("malformed regex", regexp_start,
                                         t.index);

              error = true;
              break;
            }
            // Let temporary position be tokenizer’s next index.
            size_t tmp_pos = t.next_index;

            // Run get the next code point given tokenizer.
            t.get_next_code_point();

            if (t.code_point != '?') {
              t.process_tokenizing_error("malformed regex", regexp_start,
                                         t.index);

              error = true;
              break;
            }
            t.next_index = tmp_pos;
          }
          // 7. Set regexp position to tokenizer’s next index.
          regexp_position = t.next_index;
        }

        // If error is true continue.
        if (error) break;

        if (depth) {
          t.process_tokenizing_error("malformed regex", regexp_start, t.index);
          break;
        }

        // 8.  Let regexp length be regexp position − regexp start − 1.
        if ((regexp_position - regexp_start - 1) == 0) {
          t.process_tokenizing_error("malformed regex", regexp_start, t.index);
          break;
        }

        t.add_token(TOKEN_TYPE::REGEXP, regexp_start, regexp_position);
        break;
      }
      default: {
        // TODO: maybe group the TOKEN_TYPE::CHARs to make tokens cheaper
        t.add_token(TOKEN_TYPE::CHAR);
        break;
      }
    }
  }
  t.add_token(TOKEN_TYPE::END);
  return t.token_list;
}

}  // namespace ada::urlpattern