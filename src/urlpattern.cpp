#include <_ctype.h>
#include "ada/unicode.h"
#include "ada/urlpattern.h"
#include "ada/ada_idna.h"
#include "ada/implementation.h"

#include <string>
#include <vector>
#include <string_view>
#include <type_traits>
#include <typeinfo>
#include <cassert>

namespace ada {

const static std::u32string DUMMY_URL = U"://dummy.test";

ada_really_inline bool is_valid_name_code_point(const char32_t &c,
                                                bool is_first) noexcept {
  return is_first ? unicode::is_valid_identifier_start(c)
                  : unicode::is_valid_identifier_part(c);
}

ada_really_inline bool is_ascii(char32_t c) { return c < 0x80; }

// https://wicg.github.io/urlpattern/#canonicalize-a-protocol
ada_really_inline std::u32string_view canonicalize_protocol(
    std::u32string_view protocol) {
  // If value is the empty string, return value.
  if (protocol.empty()) return protocol;

  // Let dummyURL be a new URL record.
  // Let parseResult be the result of running the basic URL parser given value
  // followed by "://dummy.test", with dummyURL as url.

  // TODO: make it cheaper
  std::u32string url = std::u32string(protocol) + DUMMY_URL;

  auto utf8_size = ada::idna::utf8_length_from_utf32(url.data(), url.size());
  std::string final_utf8_url(utf8_size, '\0');
  ada::idna::utf32_to_utf8(url.data(), url.size(), final_utf8_url.data());

  if (ada::can_parse(final_utf8_url)) {
    return protocol;
  }
  throw std::invalid_argument("invalid protocol scheme");
}

// https://wicg.github.io/urlpattern/#compile-a-component
ada_really_inline std::string_view compile_component(
    std::u32string_view input, std::function<std::u32string_view> &callback,
    urlpattern_options &options) {
  // If input is null, then set input to "*".
  if (input.empty()) return "*";
}

// ########## TOKENIZER ##########
#pragma region TOKENIZER

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

struct TOKEN {
  TOKEN_TYPE type;
  size_t value_start;
  size_t value_end;
};

enum class POLICY { STRICT, LENIENT };

ada_really_inline std::vector<TOKEN> tokenize(std::u32string_view input,
                                              POLICY policy) {
  std::vector<TOKEN> tokens{};
  size_t input_size = input.size();

  const auto error_or_invalid = [&](const std::string_view msg,
                                    size_t &value_start, size_t &value_end) {
    if (policy != POLICY::LENIENT) {
      throw std::invalid_argument(std::string(msg));
    }
    tokens.push_back({TOKEN_TYPE::INVALID_CHAR, value_start, value_end});
  };

  size_t index = 0;
  while (index < input_size) {
    switch (input[index]) {
      case '*': {
        tokens.push_back({TOKEN_TYPE::ASTERISK, index, index});
        ++index;
        break;
      }
      case '+':
      case '?': {
        tokens.push_back({TOKEN_TYPE::OTHER_MODIFIER, /*value_start*/ index,
                          /*value_end*/ index});
        ++index;
        break;
      }
      case '\\': {
        ++index;
        if (index == input_size - 1) {
          error_or_invalid("should scape something", /*value_start*/ index,
                           /*value_end*/ index);
        }

        tokens.push_back({TOKEN_TYPE::ESCAPED_CHAR, /*value_start*/ index,
                          /*value_end*/ index});
        break;
      }
      case '{': {
        tokens.push_back({TOKEN_TYPE::OPEN, /*value_start*/ index,
                          /*value_end*/ index});
        ++index;
        break;
      }
      case '}': {
        tokens.push_back({TOKEN_TYPE::CLOSE, /*value_start*/ index,
                          /*value_end*/ index});
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
                           /*value_start*/ index,
                           /*value_end*/ index);
          continue;
        }

        tokens.push_back({TOKEN_TYPE::NAME, start, end});

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
            error_or_invalid("invalid char for regex", regexp_start, regexp);

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

          tokens.push_back({TOKEN_TYPE::REGEXP, regexp_start, regexp});
          index = regexp;
        }
      }
    }

    // TODO: maybe group the TOKEN_TYPE::CHARs to make tokens cheaper
    tokens.push_back({TOKEN_TYPE::CHAR, /*value_start*/ index,
                      /*value_end*/ index});
  }

  tokens.push_back({TOKEN_TYPE::END, /*value_start*/ index,
                    /*value_end*/ index});
  return tokens;
}
#pragma endregion TOKENIZER

// ########## CONSTRUCTOR STRING PARSER ##########
#pragma region CONSTRUCTOR STRING PARSER

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
struct constructor_string_parser {
  constructor_string_parser(std::u32string_view input);

  // https://wicg.github.io/urlpattern/#parse-a-constructor-string
  ada_really_inline void parse();

  // https://wicg.github.io/urlpattern/#change-state
  ada_really_inline void change_state(PARSER_STATE new_state, size_t skip);

  // https://wicg.github.io/urlpattern/#rewind
  ada_really_inline void rewind();

  // https://wicg.github.io/urlpattern/#rewind-and-set-state
  ada_really_inline void rewind_and_set_state(PARSER_STATE new_state);

  // https://wicg.github.io/urlpattern/#is-a-hash-prefix
  ada_really_inline bool is_hash_prefix();

  // https://wicg.github.io/urlpattern/#is-a-search-prefix
  ada_really_inline bool is_search_prefix();

  // https://wicg.github.io/urlpattern/#is-a-non-special-pattern-char
  ada_really_inline bool is_nonspecial_pattern_char(const char32_t &c);

  // https://wicg.github.io/urlpattern/#get-a-safe-token
  ada_really_inline TOKEN *get_safe_token(size_t &index);

  // https://wicg.github.io/urlpattern/#is-a-group-open
  ada_really_inline bool is_group_open();

  // https://wicg.github.io/urlpattern/#is-a-group-close
  ada_really_inline bool is_group_close();

  // https://wicg.github.io/urlpattern/#is-a-protocol-suffix
  ada_really_inline bool is_protocol_suffix();

  // https://wicg.github.io/urlpattern/#compute-protocol-matches-a-special-scheme-flag
  ada_really_inline void compute_protocol_matches_special_scheme_flag();

  // https://wicg.github.io/urlpattern/#make-a-component-string
  ada_really_inline std::u32string_view make_component_string();

  std::u32string_view input;
  std::vector<TOKEN> token_list;
  size_t component_start = 0;
  size_t token_index = 0;
  size_t token_increment = 0;
  size_t group_depth = 0;
  size_t hostname_ipv6_bracket_depth = 0;
  bool protocol_matches_special_scheme = false;
  PARSER_STATE state = INIT;
  urlpattern_init result = urlpattern_init();
};

// https://wicg.github.io/urlpattern/#constructor-string-parser
constructor_string_parser::constructor_string_parser(std::u32string_view view) {
  input = view;
  token_list = tokenize(view, POLICY::LENIENT);
}

// https://wicg.github.io/urlpattern/#parse-a-constructor-string
ada_really_inline void constructor_string_parser::parse() {
  // 2. While parser’s token index is less than parser’s token list size:
  while (token_index < token_list.size()) {
    // Set parser’s token increment to 1.
    token_increment = 1;
    // If parser’s token list[parser’s token index]'s type is "end" then:

    if (token_list[token_index].type == TOKEN_TYPE::END) {
      if (state == INIT) {
        // If parser’s state is "init":
        // Run rewind given parser.
        rewind();

        // We next determine at which component the relative pattern begins.
        // Relative pathnames are most common, but URLs and URLPattern
        // constructor strings can begin with the search or hash components as
        // well.

        // If the result of running is a hash prefix given parser is true, then
        // run change state given parser, "hash" and 1.
        if (is_hash_prefix()) {
          change_state(HASH, 1);
        } else if (is_search_prefix()) {
          // Else if the result of running is a search prefix given parser is
          // true
          // Run change state given parser, "search" and 1
          // Set parser’s result["hash"] to the empty string.
          change_state(SEARCH, 1);
          result.hash = "";
        } else {
          // Run change state given parser, "pathname" and 0.
          change_state(PATHNAME, 0);
          // Set parser’s result["search"] to the empty string.
          result.search = "";
          result.hash = "";
        }
        // Increment parser’s token index by parser’s token increment.
        token_index += token_increment;
        continue;
      }

      if (state == AUTHORITY) {
        // If we reached the end of the string in the "authority" state, then we
        // failed to find an "@". Therefore there is no username or password.

        // Run rewind and set state given parser, and "hostname".
        rewind_and_set_state(PARSER_STATE::HOSTNAME);
        // Increment parser’s token index by parser’s token increment.
        token_index += token_increment;

        continue;
      }

      // Run change state given parser, "done" and 0.
      change_state(PARSER_STATE::DONE, 0);
      break;
    }

    if (is_group_open()) {
      // Increment parser’s group depth by 1.
      ++group_depth;
      // Increment parser’s token index by parser’s token increment.
      token_index += token_increment;
      continue;
    }

    // If parser’s group depth is greater than 0:
    if (group_depth > 0) {
      // If the result of running is a group close given parser is true, then
      // decrement parser’s group depth by 1.
      if (is_group_close()) {
        --group_depth;
      } else {
        // Increment parser’s token index by parser’s token increment.
        token_index += token_increment;
        continue;
      }
    }

    // Switch on parser’s state and run the associated steps:
    switch (state) {
      case INIT: {
        if (is_protocol_suffix()) {
          // We found a protocol suffix, so this must be an absolute URLPattern
          // constructor string. Therefore initialize all component to the empty
          // string.
          result.username = "";
          result.password = "";
          result.hostname = "";
          result.port = "";
          result.pathname = "";
          result.search = "";
          result.hash = "";

          // Run rewind and set state given parser and "protocol".
          rewind_and_set_state(PROTOCOL);
        }
        break;
      }
      case PROTOCOL: {
        if (is_protocol_suffix()) {
        }
      }
    }
  }
}

// https://wicg.github.io/urlpattern/#change-state
ada_really_inline void constructor_string_parser::change_state(
    PARSER_STATE new_state, size_t skip) {
  // 1. If parser’s state is not "init", not "authority", and not "done", then
  // set parser’s result[parser’s state] to the result of running make a
  // component string given parser.
  if (state != INIT && state != AUTHORITY && state != DONE) {
    // TODO improve this:
    switch (state) {
      case PROTOCOL:
        result.protocol = "";
        break;
      case USERNAME:
        result.username = "";
        break;
      case PASSWORD:
        result.password = "";
        break;
      case HOSTNAME:
        result.hostname = "";
        break;
      case PORT:
        result.port = "";
        break;
      case PATHNAME:
        result.pathname = "";
        break;
      case SEARCH:
        result.search = "";
        break;
      case HASH:
        result.hash = "";
        break;
      default:
        break;
    }
  }
  // 2. Set parser’s state to new state.
  state = new_state;
  // 3. Increment parser’s token index by skip.
  token_index += skip;
  // 4. Set parser’s component start to parser’s token index.
  component_start = token_index;
  // 5. Set parser’s token increment to 0.
  token_increment = 0;
};

// https://wicg.github.io/urlpattern/#rewind
ada_really_inline void constructor_string_parser::rewind() {
  token_index = component_start;
  token_increment = 0;
}

// https://wicg.github.io/urlpattern/#rewind-and-set-state
ada_really_inline void constructor_string_parser::rewind_and_set_state(
    PARSER_STATE new_state) {
  // Run rewind given parser.
  // Set parser’s state to state.

  rewind();
  state = new_state;
}

// https://wicg.github.io/urlpattern/#is-a-hash-prefix
ada_really_inline bool constructor_string_parser::is_hash_prefix() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index and "#".
  return is_nonspecial_pattern_char('#');
}

// https://wicg.github.io/urlpattern/#is-a-search-prefix
ada_really_inline bool constructor_string_parser::is_search_prefix() {
  // If result of running is a non-special pattern char given parser, parser’s
  // token index and "?" is true, then return true.
  if (is_nonspecial_pattern_char('?')) {
    return true;
  }

  // If parser’s token list[parser’s token index]'s value is not "?", then
  // return false.

  TOKEN *token = &token_list[token_index];

  // TODO: improve this:
  if (token->value_end - token->value_start != 0) return false;

  const char32_t c = '?';
  if (input.find(&c, token->value_start, 1) == std::u32string_view::npos) {
    return false;
  }

  // Let previous index be parser’s token index − 1.
  size_t prev_index = token_index - 1;
  if (prev_index < 0) return true;

  // Let previous token be the result of running get a safe token given parser
  // and previous index.
  TOKEN *prev_safe_token = get_safe_token(prev_index);

  // If any of the following are true, then return false:
  //
  //   previous token’s type is "name".
  //   previous token’s type is "regexp".
  //   previous token’s type is "close".
  //   previous token’s type is "asterisk".
  if (prev_safe_token->type == TOKEN_TYPE::NAME ||
      prev_safe_token->type == TOKEN_TYPE::REGEXP ||
      prev_safe_token->type == TOKEN_TYPE::CLOSE ||
      prev_safe_token->type == TOKEN_TYPE::ASTERISK) {
    return false;
  }

  return true;
}

// https://wicg.github.io/urlpattern/#is-a-non-special-pattern-char
ada_really_inline bool constructor_string_parser::is_nonspecial_pattern_char(
    const char32_t &c) {
  // 1. Let token be the result of running get a safe token given parser and
  // index.
  TOKEN *safe_token = get_safe_token(token_index);

  // 2. If token’s value is not value, then return false.
  //

  // TODO: improve this:
  if (safe_token->value_end - safe_token->value_start != 0) return false;

  if (input.find(&c, safe_token->value_start, 1) == std::u32string_view::npos) {
    return false;
  }

  // 3. If any of the following are true :
  // token’s type is "char";
  // token’s type is "escaped-char";
  // or token’s type is "invalid-char",
  // then return true.
  if (safe_token->type == TOKEN_TYPE::CHAR ||
      safe_token->type == TOKEN_TYPE::ESCAPED_CHAR ||
      safe_token->type == TOKEN_TYPE::INVALID_CHAR) {
    return true;
  }
  return false;
}

// https://wicg.github.io/urlpattern/#get-a-safe-token
ada_really_inline TOKEN *constructor_string_parser::get_safe_token(
    size_t &index) {
  // 1. If index is less than parser’s token list's size, then return parser’s
  // token list[index].
  if (index < token_list.size()) return &token_list[index];
  // 2. Assert: parser’s token list's size is greater than or equal to 1.
  // TODO: messages for the asserts? conditional and then throw error?
  assert(token_list.size() >= 1);
  // 3. Let last index be parser’s token list's size − 1.
  size_t last_index = token_list.size() - 1;
  // 4. Let token be parser’s token list[last index].
  // 5. Assert: token’s type is "end".
  assert(token_list[last_index] == TOKEN_TYPE::END);
  return &token_list[last_index];
}

// https://wicg.github.io/urlpattern/#is-a-group-open
ada_really_inline bool constructor_string_parser::is_group_open() {
  // If parser’s token list[parser’s token index]'s type is "open", then
  // return true. Else return false.
  return token_list[token_index].type == TOKEN_TYPE::OPEN;
}

// https://wicg.github.io/urlpattern/#is-a-group-close
ada_really_inline bool constructor_string_parser::is_group_close() {
  // If parser’s token list[parser’s token index]'s type is "close", then
  // return
  // true. Else return false.
  return token_list[token_index].type == TOKEN_TYPE::CLOSE;
}

// https://wicg.github.io/urlpattern/#is-a-protocol-suffix
ada_really_inline bool constructor_string_parser::is_protocol_suffix() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index, and ":".
  return is_nonspecial_pattern_char(':');
}

// https://wicg.github.io/urlpattern/#compute-protocol-matches-a-special-scheme-flag
ada_really_inline void
constructor_string_parser::compute_protocol_matches_special_scheme_flag() {
  std::u32string_view protocol = make_component_string();
  // Let protocol component be the result of compiling a component given
  // protocol string, canonicalize a protocol, and default options.
}

// https://wicg.github.io/urlpattern/#make-a-component-string
ada_really_inline std::u32string_view
constructor_string_parser::make_component_string() {
  // Assert: parser’s token index is less than parser’s token list's size.
  assert(token_index < token_list.size());

  // Let token be parser’s token list[parser’s token index].
  // TOKEN *token = &token_list[token_index];

  //  Let component start token be the result of running get a safe token given
  //  parser and parser’s component start.
  TOKEN *safe_token = get_safe_token(component_start);

  // Let component start input index be component start token’s index.
  size_t component_start_index = safe_token->value_start;

  // Let end index be token’s index.
  size_t end = token_list[token_index].value_start;

  // Return the code point substring from component start input index to end
  // index within parser’s input.
  return input.substr(component_start_index, end);
}
#pragma endregion CONSTRUCTOR STRING PARSER

// The new URLPattern(input, baseURL, options) constructor steps are:
// Run initialize given this, input, baseURL, and options.
urlpattern::urlpattern(std::string_view input,
                       std::optional<std::string_view> base_url,
                       std::optional<urlpattern_options> &options) {
  // convert input to utf32
}

}  // namespace ada
