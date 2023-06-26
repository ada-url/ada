#include "ada/implementation.h"
#include <cassert>
#include <string_view>

#include "ada/urlpattern_tokenizer.h"
#include "ada/urlpattern_constructor_string_parser.h"

namespace ada::urlpattern {

// https://wicg.github.io/urlpattern/#constructor-string-parser
ada_really_inline constructor_string_parser::constructor_string_parser(
    std::u32string_view view) {
  input = view;
  token_list = tokenize(view, POLICY::LENIENT);
}

// https://wicg.github.io/urlpattern/#parse-a-constructor-string
urlpattern_init parse_contructor_string(std::u32string_view input) {
  // 1. Let parser be a new constructor string parser whose input is input and
  // token list is the result of running tokenize given input and "lenient".
  auto parser = constructor_string_parser(input);

  // 2. While parser’s token index is less than parser’s token list size:
  while (parser.token_index < parser.token_list.size()) {
    // 1. Set parser’s token increment to 1.
    parser.token_increment = 1;

    // 2. If parser’s token list[parser’s token index]'s type is "end" then:
    if (parser.token_list[parser.token_index].type == TOKEN_TYPE::END) {
      // 1. If parser’s state is "init":
      if (parser.state == PARSER_STATE::INIT) {
        // 1. Run rewind given parser.
        parser.rewind();

        // We next determine at which component the relative pattern begins.
        // Relative pathnames are most common, but URLs and URLPattern
        // constructor strings can begin with the search or hash components as
        // well.

        // 2. If the result of running is a hash prefix given parser is true,
        // then run change state given parser, "hash" and 1.
        if (parser.is_hash_prefix()) {
          parser.change_state(PARSER_STATE::HASH, 1);
        }
        // Else if the result of running is a search prefix given parser is
        // true:
        else if (parser.is_search_prefix()) {
          // Run change state given parser, "search" and 1
          // Set parser’s result["hash"] to the empty string.
          parser.change_state(PARSER_STATE::SEARCH, 1);
          parser.result.hash = "";
        } else {
          // Run change state given parser, "pathname" and 0.
          parser.change_state(PARSER_STATE::PATHNAME, 0);
          // Set parser’s result["search"] to the empty string.
          parser.result.search = "";
          // Set parser’s result["hash"] to the empty string.
          parser.result.hash = "";
        }
        // Increment parser’s token index by parser’s token increment.
        parser.token_index += parser.token_increment;
        continue;
      }

      // If parser’s state is "authority":
      if (parser.state == PARSER_STATE::AUTHORITY) {
        // If we reached the end of the string in the "authority" state, then
        // we failed to find an "@". Therefore there is no username or
        // password.

        //  1. Run rewind and set state given parser, and "hostname".
        parser.rewind_and_set_state(PARSER_STATE::HOSTNAME);

        // Increment parser’s token index by parser’s token increment.
        parser.token_index += parser.token_increment;
        continue;
      }

      // 3. Run change state given parser, "done" and 0.
      parser.change_state(PARSER_STATE::DONE, 0);
      break;
    }

    // 3. If the result of running is a group open given parser is true:
    if (parser.is_group_open()) {
      // 1. Increment parser’s group depth by 1.
      ++parser.group_depth;
      // 2. Increment parser’s token index by parser’s token increment.
      parser.token_index += parser.token_increment;
      continue;
    }

    // 4. If parser’s group depth is greater than 0:
    if (parser.group_depth > 0) {
      //  1. If the result of running is a group close given parser is true,
      //  then decrement parser’s group depth by 1.
      if (parser.is_group_close()) {
        --parser.group_depth;
      } else {
        // 1. Increment parser’s token index by parser’s token increment.
        parser.token_index += parser.token_increment;
        continue;
      }
    }

    // 5. Switch on parser’s state and run the associated steps:
    switch (parser.state) {
      case PARSER_STATE::INIT: {
        // If the result of running is a protocol suffix given parser is true:
        if (parser.is_protocol_suffix()) {
          // We found a protocol suffix, so this must be an absolute
          // URLPattern constructor string. Therefore initialize all component
          // to the empty string.

          parser.result.username = "";
          parser.result.password = "";
          parser.result.hostname = "";
          parser.result.port = "";
          parser.result.pathname = "";
          parser.result.search = "";
          parser.result.hash = "";

          // Run rewind and set state given parser and "protocol".
          parser.rewind_and_set_state(PARSER_STATE::PROTOCOL);
        }
        break;
      }
      case PARSER_STATE::PROTOCOL: {
        // 1. If the result of running is a protocol suffix given parser is
        // true:s
        if (parser.is_protocol_suffix()) {
          // 1. Run compute protocol matches a special scheme flag given
          // parser.
          parser.compute_protocol_matches_special_scheme_flag();
          //          We need to eagerly compile the protocol component to
          //          determine if it matches any special schemes. If it
          //          does then certain special rules apply. It determines
          //          if the pathname defaults to a "/" and also whether we
          //          will look for the username, password, hostname, and
          //          port components. Authority slashes can also cause us
          //          to look for these components as well. Otherwise we
          //          treat this as an "opaque path URL" and go straight to
          //          the pathname component.

          // 2. If parser’s protocol matches a special scheme flag is true,
          // then set parser’s result["pathname"] to "/".
          if (parser.protocol_matches_special_scheme_flag) {
            parser.result.pathname = "/";
          }
          // 3. Let next state be "pathname".
          PARSER_STATE next_state = PARSER_STATE::PATHNAME;

          // 4. Let skip be 1.
          uint8_t skip = 1;
          // 5. If the result of running next is authority slashes given
          // parser is true.
          if (parser.next_is_authority_slashes()) {
            // Set next state to "authority".
            next_state = PARSER_STATE::AUTHORITY;

            // Set skip to 3.
            skip = 3;
          }
          // Else if parser’s protocol matches a special scheme flag is true,
          // then set next state to "authority".
          else if (parser.protocol_matches_special_scheme_flag) {
            next_state = PARSER_STATE::AUTHORITY;
          }
          // 7. Run change state given parser, next state, and skip.
          parser.change_state(next_state, skip);
        }
        break;
      }
      case PARSER_STATE::AUTHORITY: {
        // 1. If the result of running is an identity terminator given parser
        // is true, then run rewind and set state given parser and "username".
        if (parser.is_identity_terminator()) {
          parser.rewind_and_set_state(PARSER_STATE::USERNAME);
        }
        // Else if any of the following are true:
        //  the result of running is a pathname start given parser;
        //  the result of running is a search prefix given parser; or
        //  the result of running is a hash prefix given parser,
        // then run rewind and set state given parser and "hostname".
        else if (parser.is_pathname_start() || parser.is_search_prefix() ||
                 parser.is_hash_prefix()) {
          parser.rewind_and_set_state(PARSER_STATE::HOSTNAME);
        }
        break;
      }
      case PARSER_STATE::USERNAME: {
        // 1. If the result of running is a password prefix given parser is
        // true, then run change state given parser, "password", and 1.
        if (parser.is_password_prefix()) {
          parser.change_state(PARSER_STATE::PASSWORD, 1);
        }
        // 2. Else if the result of running is an identity terminator given
        // parser is true, then run change state given parser, "hostname",
        // and 1.
        else if (parser.is_identity_terminator()) {
          parser.change_state(PARSER_STATE::HOSTNAME, 1);
        }
        break;
      }
      case PARSER_STATE::PASSWORD: {
        // 1. If the result of running is an identity terminator given parser
        // is true, then run change state given parser, "hostname", and 1.
        if (parser.is_identity_terminator()) {
          parser.change_state(PARSER_STATE::HOSTNAME, 1);
        }
        break;
      }
      case PARSER_STATE::HOSTNAME: {
        // 1. If the the result of running is an IPv6 open given parser is
        // true, then increment parser’s hostname IPv6 bracket depth by 1.
        if (parser.is_ipv6_open()) {
          ++parser.hostname_ipv6_bracket_depth;
        }
        // 2. Else if the the result of running is an IPv6 close given parser
        // is true, then decrement parser’s hostname IPv6 bracket depth by 1.
        else if (parser.is_ipv6_close()) {
          --parser.hostname_ipv6_bracket_depth;
        }
        // 3. Else if the result of running is a port prefix given parser is
        // true and parser’s hostname IPv6 bracket depth is zero, then run
        // change state given parser, "port", and 1.
        else if (parser.is_port_prefix() &&
                 parser.hostname_ipv6_bracket_depth == 0) {
          parser.change_state(PARSER_STATE::PORT, 1);
        }
        // 4. Else if the result of running is a pathname start given parser
        // is true, then run change state given parser, "pathname", and 0.
        if (parser.is_pathname_start()) {
          parser.change_state(PARSER_STATE::PATHNAME, 0);
        }
        // 5. Else if the result of running is a search prefix given parser is
        // true, then run change state given parser, "search", and 1.
        if (parser.is_search_prefix()) {
          parser.change_state(PARSER_STATE::SEARCH, 1);
        }
        // 6. Else if the result of running is a hash prefix given parser is
        // true, then run change state given parser, "hash", and 1.
        if (parser.is_hash_prefix()) {
          parser.change_state(PARSER_STATE::HASH, 1);
        }
        break;
      }
      case PARSER_STATE::PORT: {
        // 1. If the result of running is a pathname start given parser is
        // true, then run change state given parser, "pathname", and 0.
        if (parser.is_pathname_start()) {
          parser.change_state(PARSER_STATE::PATHNAME, 0);
        }
        // 2. Else if the result of running is a search prefix given parser is
        // true, then run change state given parser, "search", and 1.
        else if (parser.is_search_prefix()) {
          parser.change_state(PARSER_STATE::SEARCH, 1);
        }
        // 3. Else if the result of running is a hash prefix given parser is
        // true, then run change state given parser, "hash", and 1.
        if (parser.is_hash_prefix()) {
          parser.change_state(PARSER_STATE::HASH, 1);
        }
      }
      case PARSER_STATE::PATHNAME: {
        // 1. If the result of running is a search prefix given parser is
        // true, then run change state given parser, "search", and 1.
        if (parser.is_search_prefix()) {
          parser.change_state(PARSER_STATE::SEARCH, 1);
        }
        // 2. Else if the result of running is a hash prefix given parser is
        // true, then run change state given parser, "hash", and 1.
        else if (parser.is_hash_prefix()) {
          parser.change_state(PARSER_STATE::HASH, 1);
        }
        break;
      }
      case PARSER_STATE::SEARCH: {
        // 1. If the result of running is a hash prefix given parser is true,
        // then run change state given parser, "hash", and 1.
        if (parser.is_hash_prefix()) {
          parser.change_state(PARSER_STATE::HASH, 1);
        }
        break;
      }
      case PARSER_STATE::HASH: {
        // do nothing;
        break;
      }
      case PARSER_STATE::DONE: {
        // 1. Assert: This step is never reached.
        assert(false);
      }
    }
    // 6. Increment parser’s token index by parser’s token increment.
    parser.token_index += parser.token_increment;
  }

  // Return parser’s result.
  return parser.result;
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

// https://wicg.github.io/urlpattern/#is-a-pathname-start
ada_really_inline bool constructor_string_parser::is_pathname_start() {
  // 1. Return the result of running is a non-special pattern char given
  // parser, parser’s token index, and "/".
  return is_nonspecial_pattern_char(token_index, U"/");
}

// https://wicg.github.io/urlpattern/#is-an-ipv6-open
ada_really_inline bool constructor_string_parser::is_ipv6_open() {
  // 1, Return the result of running is a non-special pattern char given
  // parser, parser’s token index, and "[".
  return is_nonspecial_pattern_char(token_index, U"[");
}

// https://wicg.github.io/urlpattern/#is-an-ipv6-close
ada_really_inline bool constructor_string_parser::is_ipv6_close() {
  // 1. Return the result of running is a non-special pattern char given
  // parser, parser’s token index, and "]".
  return is_nonspecial_pattern_char(token_index, U"]");
}

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

// https://wicg.github.io/urlpattern/#is-a-password-prefix
ada_really_inline bool constructor_string_parser::is_password_prefix() {
  // 1. Return the result of running is a non-special pattern char given
  // parser, parser’s token index, and ":".
  return is_nonspecial_pattern_char(token_index, U":");
}

// https://wicg.github.io/urlpattern/#is-an-identity-terminator
ada_really_inline bool constructor_string_parser::is_identity_terminator() {
  // 1. Return the result of running is a non-special pattern char given
  // parser, parser’s token index, and "@".
  return is_nonspecial_pattern_char(token_index, U"@");
}

// https://wicg.github.io/urlpattern/#is-a-hash-prefix
ada_really_inline bool constructor_string_parser::is_hash_prefix() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index and "#".
  return is_nonspecial_pattern_char(token_index, U"#");
}

// https://wicg.github.io/urlpattern/#is-a-search-prefix
ada_really_inline bool constructor_string_parser::is_search_prefix() {
  // 1. If result of running is a non-special pattern char given parser,
  // parser’s token index and "?" is true, then return true.
  if (is_nonspecial_pattern_char(token_index, U"?")) {
    return true;
  }

  // 2. If parser’s token list[parser’s token index]'s value is not "?", then
  // return false.
  if (token_list[token_index].value.compare(U"?") != 0) {
    return false;
  }

  // 3. Let previous index be parser’s token index − 1.
  size_t prev_index = token_index - 1;
  // 4. If previous index is less than 0, then return true.
  if (prev_index < 0) return true;

  // 5. Let previous token be the result of running get a safe token given
  // parser and previous index.
  token *prev_token = get_safe_token(prev_index);

  // 6. If any of the following are true, then return false:
  //   previous token’s type is "name".
  //   previous token’s type is "regexp".
  //   previous token’s type is "close".
  //   previous token’s type is "asterisk".

  if (prev_token->type == TOKEN_TYPE::NAME ||
      prev_token->type == TOKEN_TYPE::REGEXP ||
      prev_token->type == TOKEN_TYPE::CLOSE ||
      prev_token->type == TOKEN_TYPE::ASTERISK) {
    return false;
  }

  return true;
}

// https://wicg.github.io/urlpattern/#next-is-authority-slashes
ada_really_inline bool constructor_string_parser::next_is_authority_slashes() {
  // 1. If the result of running is a non-special pattern char given parser,
  // parser’s token index + 1, and "/" is false, then return false.
  if (!is_nonspecial_pattern_char(token_index + 1, U"/")) {
    return false;
  }

  // 2. If the result of running is a non-special pattern char given parser,
  // parser’s token index + 2, and "/" is false, then return false.
  if (!is_nonspecial_pattern_char(token_index + 2, U"/")) {
    return false;
  }

  return true;
}

// https://wicg.github.io/urlpattern/#is-a-non-special-pattern-char
ada_really_inline bool constructor_string_parser::is_nonspecial_pattern_char(
    size_t index, const char32_t *value) {
  // 1. Let token be the result of running get a safe token given parser and
  // index.
  token *safe_token = get_safe_token(index);

  // 2. If token’s value is not value, then return false.
  if (safe_token->value.compare(std::u32string_view(value)) != 0) {
    return false;
  }

  // If any of the following are true:
  //
  //   token’s type is "char";
  //   token’s type is "escaped-char"; or
  //   token’s type is "invalid-char",
  //
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
  assert(token_list[last_index].type == TOKEN_TYPE::END);
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
  return is_nonspecial_pattern_char(token_index, U":");
}

// https://wicg.github.io/urlpattern/#is-a-port-prefix
ada_really_inline bool constructor_string_parser::is_port_prefix() {
  // 1. Return the result of running is a non-special pattern char given
  // parser, parser’s token index, and ":".
  return is_nonspecial_pattern_char(token_index, U":");
}

// https://wicg.github.io/urlpattern/#compute-protocol-matches-a-special-scheme-flag
ada_really_inline void
constructor_string_parser::compute_protocol_matches_special_scheme_flag() {
  // 1. Let protocol string be the result of running make a component string
  // given parser.
  std::u32string_view protocol_string = make_component_string();

  // 2. Let protocol component be the result of compiling a component given
  // protocol string, canonicalize a protocol, and default options.
  

  // 1. Let protocol component be the result of compiling a component given
  // protocol string, canonicalize a protocol, and default options.
}

// https://wicg.github.io/urlpattern/#make-a-component-string
ada_really_inline std::u32string_view
constructor_string_parser::make_component_string() {
  // 1. Assert: parser’s token index is less than parser’s token list's size.
  assert(token_index < token_list.size());

  // 2. Let token be parser’s token list[parser’s token index].
  auto *t = &token_list[token_index];

  // 3. Let component start token be the result of running get a safe token
  // given parser and parser’s component start.
  auto component_start_token = get_safe_token(component_start);

  // 4. Let component start input index be component start token’s index.
  size_t component_start_input_index = component_start_token->index;

  // 5. Let end index be token’s index.
  size_t end_index = t->index;

  // 6. Return the code point substring from component start input index to end
  // index within parser’s input.
  return input.substr(component_start_input_index, end_index);
}

}  // namespace ada::urlpattern
