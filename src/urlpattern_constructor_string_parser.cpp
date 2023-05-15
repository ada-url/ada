#include "ada/implementation.h"

#include "ada/urlpattern_tokenizer.h"
#include "ada/urlpattern_constructor_string_parser.h"

namespace ada::urlpattern {

// https://wicg.github.io/urlpattern/#canonicalize-a-protocol
// TODO: maybe make it receive a utf8 string at this point already
ada_really_inline std::u32string_view canonicalize_protocol(
    std::u32string_view protocol) {
  // If value is the empty string, return value.
  if (protocol.empty()) return protocol;

  // Let dummyURL be a new URL record.
  // Let parseResult be the result of running the basic URL parser given value
  // followed by "://dummy.test", with dummyURL as url.

  // TODO: make it cheaper
  std::u32string url = std::u32string(protocol) + U"://dummy.test";

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
    u32urlpattern_options &options) {
  // If input is null, then set input to "*".
  if (input.empty()) input = U"*";
}

// https://wicg.github.io/urlpattern/#constructor-string-parser
ada_really_inline constructor_string_parser::constructor_string_parser(
    std::u32string_view view) {
  input = view;
  token_list = tokenize(view, POLICY::LENIENT);
}

// https://wicg.github.io/urlpattern/#parse-a-constructor-string
ada_really_inline void constructor_string_parser::parse_contructor_string(
    std::u32string_view input) {
  // Let parser be a new constructor string parser whose input is input and
  // token list is the result of running tokenize given input and "lenient".
  auto p = constructor_string_parser(input);

  // 2. While parser’s token index is less than parser’s token list size:
  while (p.token_index < p.token_list.size()) {
    // Set parser’s token increment to 1.
    p.token_increment = 1;
    // If parser’s token list[parser’s token index]'s type is "end" then:

    if (p.token_list[p.token_index].type == TOKEN_TYPE::END) {
      if (p.state == PARSER_STATE::INIT) {
        // If parser’s state is "init":
        // Run rewind given parser.
        p.rewind();

        // We next determine at which component the relative pattern begins.
        // Relative pathnames are most common, but URLs and URLPattern
        // constructor strings can begin with the search or hash components as
        // well.

        // If the result of running is a hash prefix given parser is true, then
        // run change state given parser, "hash" and 1.
        if (p.is_hash_prefix()) {
          p.change_state(PARSER_STATE::HASH, 1);
        } else if (p.is_search_prefix()) {
          // Else if the result of running is a search prefix given parser is
          // true
          // Run change state given parser, "search" and 1
          // Set parser’s result["hash"] to the empty string.
          p.change_state(PARSER_STATE::SEARCH, 1);
          p.result.hash = "";
        } else {
          // Run change state given parser, "pathname" and 0.
          p.change_state(PARSER_STATE::PATHNAME, 0);
          // Set parser’s result["search"] to the empty string.
          p.result.search = "";
          p.result.hash = "";
        }
        // Increment parser’s token index by parser’s token increment.
        p.token_index += p.token_increment;
        continue;
      }

      if (p.state == PARSER_STATE::AUTHORITY) {
        // If we reached the end of the string in the "authority" state, then we
        // failed to find an "@". Therefore there is no username or password.

        // Run rewind and set state given parser, and "hostname".
        p.rewind_and_set_state(PARSER_STATE::HOSTNAME);
        // Increment parser’s token index by parser’s token increment.
        p.token_index += p.token_increment;

        continue;
      }

      // Run change state given parser, "done" and 0.
      p.change_state(PARSER_STATE::DONE, 0);
      break;
    }

    if (p.is_group_open()) {
      // Increment parser’s group depth by 1.
      ++p.group_depth;
      // Increment parser’s token index by parser’s token increment.
      p.token_index += p.token_increment;
      continue;
    }

    // If parser’s group depth is greater than 0:
    if (p.group_depth > 0) {
      // If the result of running is a group close given parser is true, then
      // decrement parser’s group depth by 1.
      if (p.is_group_close()) {
        --p.group_depth;
      } else {
        // Increment parser’s token index by parser’s token increment.
        p.token_index += p.token_increment;
        continue;
      }
    }

    // Switch on parser’s state and run the associated steps:
    switch (p.state) {
      case PARSER_STATE::INIT: {
        if (p.is_protocol_suffix()) {
          // We found a protocol suffix, so this must be an absolute URLPattern
          // constructor string. Therefore initialize all component to the empty
          // string.
          p.result.username = "";
          p.result.password = "";
          p.result.hostname = "";
          p.result.port = "";
          p.result.pathname = "";
          p.result.search = "";
          p.result.hash = "";

          // Run rewind and set state given parser and "protocol".
          p.rewind_and_set_state(PARSER_STATE::PROTOCOL);
        }
        break;
      }
      case PARSER_STATE::PROTOCOL: {
        if (p.is_protocol_suffix()) {
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
  if (state != PARSER_STATE::INIT && state != PARSER_STATE::AUTHORITY &&
      state != PARSER_STATE::DONE) {
    // TODO improve this:
    switch (state) {
      case PARSER_STATE::PROTOCOL:
        result.protocol = "";
        break;
      case PARSER_STATE::USERNAME:
        result.username = "";
        break;
      case PARSER_STATE::PASSWORD:
        result.password = "";
        break;
      case PARSER_STATE::HOSTNAME:
        result.hostname = "";
        break;
      case PARSER_STATE::PORT:
        result.port = "";
        break;
      case PARSER_STATE::PATHNAME:
        result.pathname = "";
        break;
      case PARSER_STATE::SEARCH:
        result.search = "";
        break;
      case PARSER_STATE::HASH:
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

  token *curr_token = &token_list[token_index];

  // TODO: improve this:

  if (curr_token->value_end - curr_token->value_start != 0) return false;

  const char32_t c = '?';
  if (input.find(&c, curr_token->value_start, 1) == std::u32string_view::npos) {
    return false;
  }

  // Let previous index be parser’s token index − 1.
  size_t prev_index = token_index - 1;
  if (prev_index < 0) return true;

  // Let previous token be the result of running get a safe token given parser
  // and previous index.
  token *prev_safe_token = get_safe_token(prev_index);

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
  token *safe_token = get_safe_token(token_index);

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
ada_really_inline token *constructor_string_parser::get_safe_token(
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
  token *safe_token = get_safe_token(component_start);

  // Let component start input index be component start token’s index.
  size_t component_start_index = safe_token->value_start;

  // Let end index be token’s index.
  size_t end = token_list[token_index].value_start;

  // Return the code point substring from component start input index to end
  // index within parser’s input.
  return input.substr(component_start_index, end);
}

}  // namespace ada::urlpattern
