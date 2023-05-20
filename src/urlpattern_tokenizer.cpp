#include "ada/urlpattern_tokenizer.h"
#include "ada/unicode.h"
#include "ada/urlpattern.h"

#include <iostream>

namespace ada::urlpattern {

ada_really_inline bool is_valid_name_code_point(const char32_t &c,
                                                bool is_first) noexcept {
  return is_first ? unicode::is_valid_identifier_start(c)
                  : unicode::is_valid_identifier_part(c);
}

ada_really_inline bool is_ascii(char32_t &c) { return c < 0x80; }

// https://wicg.github.io/urlpattern/#seek-and-get-the-next-code-point
ada_really_inline void tokenizer::seek_and_get_next_code_point() {
  // Set tokenizer’s next index to index.
  index = next_index;

  // Run get the next code point given tokenizer.
  get_next_code_point();
}

// https://wicg.github.io/urlpattern/#get-the-next-code-point
ada_really_inline void tokenizer::get_next_code_point() {
  // Set tokenizer’s code point to the Unicode code point in tokenizer’s input
  // at the position indicated by tokenizer’s next index.
  code_point = input[index];

  // Increment tokenizer’s next index by 1.
  ++next_index;
}

// https://wicg.github.io/urlpattern/#add-a-token
ada_really_inline void tokenizer::add_token(TOKEN_TYPE type, size_t next_pos,
                                            size_t value_start,
                                            size_t value_end) {
  // Let token be a new token.
  token new_token = token();
  new_token.type = type;
  new_token.value_start = value_start;
  new_token.value_end = value_end;

  token_list.push_back(new_token);
  index = next_pos;
}

void tokenizer::process_tokenizing_error(std::string_view msg,
                                         size_t value_start, size_t value_end) {
  if (policy != POLICY::LENIENT) {
    throw std::invalid_argument(std::string(msg));
  }

  token_list.push_back({TOKEN_TYPE::INVALID_CHAR, value_start, value_end});
}

std::vector<token> tokenize(std::u32string_view _input,
                            ada::urlpattern::POLICY _policy) {
  // Let tokenizer be a new tokenizer.
  auto t = tokenizer();

  // Set tokenizer’s input to input.
  t.input = _input;

  // Set tokenizer’s policy to policy.
  t.policy = _policy;

  // While tokenizer’s index is less than tokenizer’s input's code point length:
  while (t.index < t.input.size()) {
    std::cout << t.code_point << std::endl;
    // Run seek and get the next code point given tokenizer and tokenizer’s
    // index.
    t.seek_and_get_next_code_point();

    switch (t.code_point) {
      case '*': {
        // Run add a token with default position and length given tokenizer and
        // "asterisk".
        t.add_token(TOKEN_TYPE::ASTERISK, t.next_index, t.index, t.index);
        continue;
      }
      case '+':
      case '?': {
        t.add_token(TOKEN_TYPE::OTHER_MODIFIER, t.next_index, t.index, t.index);
        continue;
      }
      case '\\': {
        // If tokenizer’s index is equal to tokenizer’s input's code point
        // length − 1:
        if (t.index == t.input.size() - 1) {
          // Run process a tokenizing error given tokenizer, tokenizer’s next
          // index, and tokenizer’s index.
          t.process_tokenizing_error("should scape something",
                                     /*value_start*/ t.index,
                                     /*value_end*/ t.index);
          continue;
        }

        // Run get the next code point given tokenizer.
        t.get_next_code_point();

        // Run add a token with default length given tokenizer, "escaped-char",
        // tokenizer’s next index, and escaped index.
        t.add_token(TOKEN_TYPE::ESCAPED_CHAR, t.next_index, t.index, t.index);
        continue;
      }
      case '{': {
        t.add_token(TOKEN_TYPE::OPEN, t.next_index, t.index, t.index);
        continue;
      }
      case '}': {
        t.add_token(TOKEN_TYPE::CLOSE, t.next_index, t.index, t.index);
        continue;
      }
      case ':': {
        // Let name position be tokenizer’s next index.
        size_t name_start, name_position;
        name_position = t.next_index;

        // Let name start be name position.
        name_start = name_position;

        // While name position is less than tokenizer’s input's code point
        // length:
        while (name_position < t.input.size()) {
          // Run seek and get the next code point given tokenizer and name
          // position.
          std::cout << "NEXT INDEX" << t.next_index << std::endl;
          t.seek_and_get_next_code_point();

          // Let first code point be true if name position equals name start and
          // false otherwise.
          bool first_code_point = name_position == name_start;

          // Let valid code point be the result of running is a valid name code
          // point given tokenizer’s code point and first code point.
          bool valid_code_point =
              is_valid_name_code_point(t.input[t.code_point],
                                       /*is_first=*/first_code_point);

          // If valid code point is false break.
          if (!valid_code_point) break;

          // Set name position to tokenizer’s next index.
          name_position = t.next_index;
        }
        if (name_position <= name_start) {
          t.process_tokenizing_error("missing pattern name", name_start,
                                     t.index);
          continue;
        }
        t.add_token(TOKEN_TYPE::NAME, t.next_index, name_start, name_position);
        continue;
      }
      case '(': {
        size_t regexp_start, regexp_position, depth;
        regexp_position = t.next_index;
        regexp_start = regexp_position;
        depth = 1;

        bool error = false;
        while (regexp_position < t.input.size()) {
          t.seek_and_get_next_code_point();
          if (!is_ascii(t.code_point)) {
            t.process_tokenizing_error("invalid char for regex", regexp_start,
                                       regexp_position);

            error = true;
            break;
          }
          if (t.code_point == '?' && (regexp_position == regexp_start)) {
            t.process_tokenizing_error("malformed regex", regexp_start,
                                       t.index);

            error = true;
            break;
          }
          if (t.code_point == '\\') {
            if (regexp_position == t.input.size() - 1) {
              t.process_tokenizing_error("malformed regex", regexp_start,
                                         t.index);

              error = true;
              break;
            }
            t.get_next_code_point();
            if (!is_ascii(t.code_point)) {
              t.process_tokenizing_error("invalid char for regex", regexp_start,
                                         t.index);

              error = true;
              break;
            }
            regexp_position = t.next_index;
            continue;
          }

          if (t.code_point == ')') {
            --depth;
            if (depth == 0) {
              regexp_position = t.next_index;
            }
          } else if (t.code_point == '(') {
            ++depth;
            if (regexp_position == t.input.size() - 1) {
              t.process_tokenizing_error("malformed regex", regexp_start,
                                         t.index);

              error = true;
              break;
            }
            size_t tmp_pos = t.next_index;
            t.get_next_code_point();

            if (t.code_point != '?') {
              t.process_tokenizing_error("malformed regex", regexp_start,
                                         t.index);

              error = true;
              break;
            }
            t.next_index = tmp_pos;
          }

          if (error) continue;

          if (depth) {
            t.process_tokenizing_error("malformed regex", regexp_start,
                                       t.index);
            continue;
          }

          if ((regexp_position - regexp_start) == 0) {
            t.process_tokenizing_error("malformed regex", regexp_start,
                                       t.index);
            continue;
          }

          t.add_token(TOKEN_TYPE::REGEXP, /*next_pos=*/regexp_position,
                      regexp_start, regexp_position);
          continue;
        }
      }
      default: {
        // TODO: maybe group the TOKEN_TYPE::CHARs to make tokens cheaper
        t.add_token(TOKEN_TYPE::CHAR, t.next_index, t.index, t.index);
      }
    }
  }
  t.add_token(TOKEN_TYPE::END, t.next_index, t.index, t.index);
  return t.token_list;
}

}  // namespace ada::urlpattern