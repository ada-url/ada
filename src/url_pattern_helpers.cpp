#include "ada/url_pattern_helpers.h"

#include <algorithm>
#include <optional>
#include <string>

namespace ada::url_pattern_helpers {

tl::expected<std::vector<Token>, errors> tokenize(std::string_view input,
                                                  token_policy policy) {
  ada_log("tokenize input: ", input);
  // Let tokenizer be a new tokenizer.
  // Set tokenizer’s input to input.
  // Set tokenizer’s policy to policy.
  auto tokenizer = Tokenizer(input, policy);
  // While tokenizer’s index is less than tokenizer’s input's code point length:
  while (tokenizer.index < tokenizer.input.size()) {
    // Run seek and get the next code point given tokenizer and tokenizer’s
    // index.
    tokenizer.seek_and_get_next_code_point(tokenizer.index);

    // If tokenizer’s code point is U+002A (*):
    if (tokenizer.code_point == '*') {
      // Run add a token with default position and length given tokenizer and
      // "asterisk".
      tokenizer.add_token_with_defaults(token_type::ASTERISK);
      ada_log("add ASTERISK token");
      // Continue.
      continue;
    }

    // If tokenizer’s code point is U+002B (+) or U+003F (?):
    if (tokenizer.code_point == '+' || tokenizer.code_point == '?') {
      // Run add a token with default position and length given tokenizer and
      // "other-modifier".
      tokenizer.add_token_with_defaults(token_type::OTHER_MODIFIER);
      // Continue.
      continue;
    }

    // If tokenizer’s code point is U+005C (\):
    if (tokenizer.code_point == '\\') {
      // If tokenizer’s index is equal to tokenizer’s input's code point length
      // − 1:
      if (tokenizer.index == tokenizer.input.size() - 1) {
        // Run process a tokenizing error given tokenizer, tokenizer’s next
        // index, and tokenizer’s index.
        if (auto error = tokenizer.process_tokenizing_error(
                tokenizer.next_index, tokenizer.index)) {
          ada_log("process_tokenizing_error failed");
          return tl::unexpected(*error);
        }
        continue;
      }

      // Let escaped index be tokenizer’s next index.
      auto escaped_index = tokenizer.next_index;
      // Run get the next code point given tokenizer.
      tokenizer.get_next_code_point();
      // Run add a token with default length given tokenizer, "escaped-char",
      // tokenizer’s next index, and escaped index.
      tokenizer.add_token_with_default_length(
          token_type::ESCAPED_CHAR, tokenizer.next_index, escaped_index);
      ada_log("add ESCAPED_CHAR token on next_index ", tokenizer.next_index,
              " with escaped index ", escaped_index);
      // Continue.
      continue;
    }

    // If tokenizer’s code point is U+007B ({):
    if (tokenizer.code_point == '{') {
      // Run add a token with default position and length given tokenizer and
      // "open".
      tokenizer.add_token_with_defaults(token_type::OPEN);
      ada_log("add OPEN token");
      continue;
    }

    // If tokenizer’s code point is U+007D (}):
    if (tokenizer.code_point == '}') {
      // Run add a token with default position and length given tokenizer and
      // "close".
      tokenizer.add_token_with_defaults(token_type::CLOSE);
      ada_log("add CLOSE token");
      continue;
    }

    // If tokenizer’s code point is U+003A (:):
    if (tokenizer.code_point == ':') {
      // Let name position be tokenizer’s next index.
      auto name_position = tokenizer.next_index;
      // Let name start be name position.
      auto name_start = name_position;
      // While name position is less than tokenizer’s input's code point length:
      while (name_position < tokenizer.input.size()) {
        // Run seek and get the next code point given tokenizer and name
        // position.
        tokenizer.seek_and_get_next_code_point(name_position);
        // Let first code point be true if name position equals name start and
        // false otherwise.
        bool first_code_point = name_position == name_start;
        // Let valid code point be the result of running is a valid name code
        // point given tokenizer’s code point and first code point.
        auto valid_code_point =
            idna::valid_name_code_point(tokenizer.code_point, first_code_point);
        ada_log("tokenizer.code_point=", uint32_t(tokenizer.code_point),
                " first_code_point=", first_code_point,
                " valid_code_point=", valid_code_point);
        // If valid code point is false break.
        if (!valid_code_point) break;
        // Set name position to tokenizer’s next index.
        name_position = tokenizer.next_index;
      }

      // If name position is less than or equal to name start:
      if (name_position <= name_start) {
        // Run process a tokenizing error given tokenizer, name start, and
        // tokenizer’s index.
        if (auto error = tokenizer.process_tokenizing_error(name_start,
                                                            tokenizer.index)) {
          ada_log("process_tokenizing_error failed");
          return tl::unexpected(*error);
        }
        // Continue
        continue;
      }

      // Run add a token with default length given tokenizer, "name", name
      // position, and name start.
      tokenizer.add_token_with_default_length(token_type::NAME, name_position,
                                              name_start);
      continue;
    }

    // If tokenizer’s code point is U+0028 (():
    if (tokenizer.code_point == '(') {
      // Let depth be 1.
      size_t depth = 1;
      // Let regexp position be tokenizer’s next index.
      auto regexp_position = tokenizer.next_index;
      // Let regexp start be regexp position.
      auto regexp_start = regexp_position;
      // Let error be false.
      bool error = false;

      // While regexp position is less than tokenizer’s input's code point
      // length:
      while (regexp_position < tokenizer.input.size()) {
        // Run seek and get the next code point given tokenizer and regexp
        // position.
        tokenizer.seek_and_get_next_code_point(regexp_position);

        // TODO: Optimization opportunity: The next 2 if statements can be
        // merged. If the result of running is ASCII given tokenizer’s code
        // point is false:
        if (!unicode::is_ascii(tokenizer.code_point)) {
          // Run process a tokenizing error given tokenizer, regexp start, and
          // tokenizer’s index.
          if (auto process_error = tokenizer.process_tokenizing_error(
                  regexp_start, tokenizer.index)) {
            return tl::unexpected(*process_error);
          }
          // Set error to true.
          error = true;
          break;
        }

        // If regexp position equals regexp start and tokenizer’s code point is
        // U+003F (?):
        if (regexp_position == regexp_start && tokenizer.code_point == '?') {
          // Run process a tokenizing error given tokenizer, regexp start, and
          // tokenizer’s index.
          if (auto process_error = tokenizer.process_tokenizing_error(
                  regexp_start, tokenizer.index)) {
            return tl::unexpected(*process_error);
          }
          // Set error to true;
          error = true;
          break;
        }

        // If tokenizer’s code point is U+005C (\):
        if (tokenizer.code_point == '\\') {
          // If regexp position equals tokenizer’s input's code point length − 1
          if (regexp_position == tokenizer.input.size() - 1) {
            // Run process a tokenizing error given tokenizer, regexp start, and
            // tokenizer’s index.
            if (auto process_error = tokenizer.process_tokenizing_error(
                    regexp_start, tokenizer.index)) {
              return tl::unexpected(*process_error);
            }
            // Set error to true.
            error = true;
            break;
          }
          // Run get the next code point given tokenizer.
          tokenizer.get_next_code_point();
          // If the result of running is ASCII given tokenizer’s code point is
          // false:
          if (!unicode::is_ascii(tokenizer.code_point)) {
            // Run process a tokenizing error given tokenizer, regexp start, and
            // tokenizer’s index.
            if (auto process_error = tokenizer.process_tokenizing_error(
                    regexp_start, tokenizer.index);
                process_error.has_value()) {
              return tl::unexpected(*process_error);
            }
            // Set error to true.
            error = true;
            break;
          }
          // Set regexp position to tokenizer’s next index.
          regexp_position = tokenizer.next_index;
          continue;
        }

        // If tokenizer’s code point is U+0029 ()):
        if (tokenizer.code_point == ')') {
          // Decrement depth by 1.
          depth--;
          // If depth is 0:
          if (depth == 0) {
            // Set regexp position to tokenizer’s next index.
            regexp_position = tokenizer.next_index;
            // Break.
            break;
          }
        } else if (tokenizer.code_point == '(') {
          // Otherwise if tokenizer’s code point is U+0028 (():
          // Increment depth by 1.
          depth++;
          // If regexp position equals tokenizer’s input's code point length −
          // 1:
          if (regexp_position == tokenizer.input.size() - 1) {
            // Run process a tokenizing error given tokenizer, regexp start, and
            // tokenizer’s index.
            if (auto process_error = tokenizer.process_tokenizing_error(
                    regexp_start, tokenizer.index)) {
              return tl::unexpected(*process_error);
            }
            // Set error to true.
            error = true;
            break;
          }
          // Let temporary position be tokenizer’s next index.
          auto temporary_position = tokenizer.next_index;
          // Run get the next code point given tokenizer.
          tokenizer.get_next_code_point();
          // If tokenizer’s code point is not U+003F (?):
          if (tokenizer.code_point != '?') {
            // Run process a tokenizing error given tokenizer, regexp start, and
            // tokenizer’s index.
            if (auto process_error = tokenizer.process_tokenizing_error(
                    regexp_start, tokenizer.index)) {
              return tl::unexpected(*process_error);
            }
            // Set error to true.
            error = true;
            break;
          }
          // Set tokenizer’s next index to temporary position.
          tokenizer.next_index = temporary_position;
        }
        // Set regexp position to tokenizer’s next index.
        regexp_position = tokenizer.next_index;
      }

      // If error is true continue.
      if (error) continue;
      // If depth is not zero:
      if (depth != 0) {
        // Run process a tokenizing error given tokenizer, regexp start, and
        // tokenizer’s index.
        if (auto process_error = tokenizer.process_tokenizing_error(
                regexp_start, tokenizer.index)) {
          return tl::unexpected(*process_error);
        }
        continue;
      }
      // Let regexp length be regexp position − regexp start − 1.
      auto regexp_length = regexp_position - regexp_start - 1;
      // If regexp length is zero:
      if (regexp_length == 0) {
        // Run process a tokenizing error given tokenizer, regexp start, and
        // tokenizer’s index.
        if (auto process_error = tokenizer.process_tokenizing_error(
                regexp_start, tokenizer.index)) {
          ada_log("process_tokenizing_error failed");
          return tl::unexpected(*process_error);
        }
        continue;
      }
      // Run add a token given tokenizer, "regexp", regexp position, regexp
      // start, and regexp length.
      tokenizer.add_token(token_type::REGEXP, regexp_position, regexp_start,
                          regexp_length);
      continue;
    }
    // Run add a token with default position and length given tokenizer and
    // "char".
    tokenizer.add_token_with_defaults(token_type::CHAR);
  }
  // Run add a token with default length given tokenizer, "end", tokenizer’s
  // index, and tokenizer’s index.
  tokenizer.add_token_with_default_length(token_type::END, tokenizer.index,
                                          tokenizer.index);

  ada_log("tokenizer.token_list size is: ", tokenizer.token_list.size());
  // Return tokenizer’s token list.
  return tokenizer.token_list;
}

}  // namespace ada::url_pattern_helpers