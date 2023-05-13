#include <_ctype.h>
#include "ada/unicode.h"
#include "ada/urlpattern.h"
#include "ada/ada_idna.h"

#include <vector>
#include <string_view>
#include <type_traits>
#include <typeinfo>
#include <cassert>

namespace ada {

ada_really_inline bool is_valid_name_code_point(const char32_t &c,
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
  TOKEN_TYPE type;
  std::u32string_view value;
};

ada_really_inline std::vector<TOKEN> tokenize(std::u32string_view input,
                                              POLICY policy) {
  std::vector<TOKEN> tokens{};
  size_t input_size = input.size();

  const auto error_or_invalid = [&](const std::string_view msg,
                                    const std::u32string_view value) {
    if (policy != POLICY::LENIENT) {
      throw std::invalid_argument(std::string(msg));
    }
    tokens.push_back({TOKEN_TYPE::INVALID_CHAR, value});
  };

  size_t index = 0;
  while (index < input_size) {
    switch (input[index]) {
      case '*': {
        tokens.push_back({TOKEN_TYPE::ASTERISK, input.substr(index, 1)});
        ++index;
        break;
      }
      case '+':
      case '?': {
        tokens.push_back({TOKEN_TYPE::OTHER_MODIFIER, input.substr(index, 1)});
        ++index;
        break;
      }
      case '\\': {
        ++index;
        if (index == input_size - 1) {
          error_or_invalid("should scape something", input.substr(index, 1));
        }

        tokens.push_back({TOKEN_TYPE::ESCAPED_CHAR, input.substr(index, 1)});
        break;
      }
      case '{': {
        tokens.push_back({TOKEN_TYPE::OPEN, input.substr(index, 1)});
        ++index;
        break;
      }
      case '}': {
        tokens.push_back({TOKEN_TYPE::CLOSE, input.substr(index, 1)});
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
          error_or_invalid("missing parameter name",
                           input.substr(start, end - start));
          continue;
        }

        tokens.push_back({TOKEN_TYPE::NAME, input.substr(start, end - start)});

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
            error_or_invalid("invalid char for regex", input.substr(regexp, 1));

            error = true;
            break;
          }
          if (input[regexp] == '?' && (regexp == regexp_start)) {
            error_or_invalid("malformed regex", input.substr(regexp, 1));

            error = true;
            break;
          }
          if (input[regexp] == '\\') {
            if (regexp == input_size - 1) {
              error_or_invalid("malformed regex", input.substr(regexp, 1));

              error = true;
              break;
            }
            ++regexp;
            if (!is_ascii(input[regexp])) {
              error_or_invalid("invalid char for regex",
                               input.substr(regexp, 1));

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
              error_or_invalid("malformed regex", input.substr(regexp, 1));

              error = true;
              break;
            }
            if (input[regexp + 1] != '?') {
              error_or_invalid("malformed regex", input.substr(regexp, 1));

              error = true;
              break;
            }
            ++regexp;
          }

          ++regexp;

          if (error) continue;

          if (depth) {
            error_or_invalid("malformed regex", input.substr(regexp, 1));
            break;
          }

          if ((regexp - regexp_start) == 0) {
            error_or_invalid("malformed regex", input.substr(regexp, 1));
          }

          tokens.push_back({TOKEN_TYPE::REGEXP,
                            input.substr(regexp_start, regexp - regexp_start)});
          index = regexp;
        }
      }
    }

    // TODO: maybe group the TOKEN_TYPE::CHARs to make tokens cheaper
    tokens.push_back({TOKEN_TYPE::CHAR, input.substr(index, 1)});
  }

  tokens.push_back({TOKEN_TYPE::END, input.substr(index, 1)});
  return tokens;
}

// https://wicg.github.io/urlpattern/#get-a-safe-token
ada_really_inline TOKEN get_safe_token(std::vector<TOKEN> &token_list,
                                       size_t &index) {
  // 1. If index is less than parser’s token list's size, then return parser’s
  // token list[index].
  if (index < token_list.size()) return token_list[index];
  // 2. Assert: parser’s token list's size is greater than or equal to 1.
  // TODO: messages for the asserts? conditional and then throw error?
  assert(token_list.size() >= 1);
  // 3. Let last index be parser’s token list's size − 1.
  size_t last_index = token_list.size() - 1;
  // 4. Let token be parser’s token list[last index].
  TOKEN token = token_list[last_index];
  // 5. Assert: token’s type is "end".
  assert(token.type == TOKEN_TYPE::END);
  return token;
}

// https://wicg.github.io/urlpattern/#is-a-non-special-pattern-char
ada_really_inline bool is_nonspecial_pattern_char(
    std::vector<TOKEN> &token_list, size_t &index, const char32_t &c) {
  // 1. Let token be the result of running get a safe token given parser and
  // index.
  // TODO: maybe return just the index to make it cheaper
  TOKEN token = get_safe_token(token_list, index);

  // 2. If token’s value is not value, then return false.
  if (token.value[0] == c) {
    return false;
  }

  // 3. If any of the following are true :
  // token’s type is "char";
  // token’s type is "escaped-char";
  // or token’s type is "invalid-char",
  // then return true.
  if (token.type == TOKEN_TYPE::CHAR ||
      token.type == TOKEN_TYPE::ESCAPED_CHAR ||
      token.type == TOKEN_TYPE::INVALID_CHAR) {
    return true;
  }
  return false;
}

// https://wicg.github.io/urlpattern/#is-a-hash-prefix
ada_really_inline bool is_hash_prefix(std::vector<TOKEN> &token_list,
                                      size_t &index) {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index and "#".
  return is_nonspecial_pattern_char(token_list, index, '#');
}

/*
A constructor string parser has an associated state, a string, initially set to
"init". It must be one of the following:

    "init"
    "protocol"
    "authority"
    "username"
    "password"
    "hostname"
    "port"
    "pathname"
    "search"
    "hash"
    "done"
*/

enum PARSER_STATE {
  INIT,
  PROTOCOL,
  AUTHORITY,
  USERNAME,
  PASSWORD,
  HOSTNAME,
  PORT,
  PATHNAME,
  SEARCH,
  HASH,
  DONE
};

// https://wicg.github.io/urlpattern/#constructor-string-parser
ada_really_inline urlpattern_init
contructor_string_parser(std::u32string_view input) {
  // A constructor string parser has an associated token list, a token list,
  // which must be set upon creation.
  std::vector<TOKEN> token_list = tokenize(input, POLICY::LENIENT);
  urlpattern_init result{};

  // A constructor string parser has an associated state, a string, initially
  // set to "init"
  PARSER_STATE state = INIT;

  // https://wicg.github.io/urlpattern/#change-state
  const auto change_state = [&](PARSER_STATE &new_state, size_t &skip) {
    // If parser’s state is not "init", not "authority", and not "done", then
    // set parser’s result[parser’s state] to the result of running make a
    // component string given parser.
    if (state != INIT && state != AUTHORITY && state != DONE) {
      result[""]
    }
  };

  // https://wicg.github.io/urlpattern/#rewind
  const auto rewind = [](size_t &index, size_t &token_increment) {
    index = 0;
    token_increment = 0;
  };

  size_t index = 0;
  size_t token_increment = 1;
  // While parser’s token index is less than parser’s token list size:
  while (index < token_list.size()) {
    // If parser’s token list[parser’s token index]'s type is "end" then:
    // If parser’s state is "init":
    if (token_list[index].type == TOKEN_TYPE::END) {
      if (state == INIT) {
        // If we reached the end of the string in the "init" state, then we
        // failed to find a protocol terminator and this must be a relative
        // URLPattern constructor string.

        // Run rewind given parser.  We next determine at which component the
        // relative pattern begins Relative pathnames are most common, but URLs
        // and URLPattern  constructor strings can begin with the search or hash
        // components as well.
        rewind(index, token_increment);

        // We next determine at which component the relative pattern begins.
        // Relative pathnames are most common, but URLs and URLPattern
        // constructor strings can begin with the search or hash components as
        // well.
        if (is_hash_prefix(token_list, index)) {
        }
      }
    }
  }

  return result;
}

// The new URLPattern(input, baseURL, options) constructor steps are:
// Run initialize given this, input, baseURL, and options.
urlpattern::urlpattern(std::string_view input,
                       std::optional<std::string_view> base_url,
                       std::optional<urlpattern_options> &options) {
  // convert input to utf32
}

}  // namespace ada
