/**
 * @file url_pattern-inl.h
 * @brief Declaration for the URLPattern inline functions.
 */
#ifndef ADA_URL_PATTERN_INL_H
#define ADA_URL_PATTERN_INL_H

#include "ada/common_defs.h"
#include "ada/url_pattern.h"

#include <string_view>

namespace ada {

inline bool url_pattern_component::has_regexp_groups() const noexcept
    ada_lifetime_bound {
  return has_regexp_groups_;
}

inline std::string_view url_pattern_component::get_pattern() const noexcept
    ada_lifetime_bound {
  return pattern;
}

inline std::string_view url_pattern_component::get_regexp() const noexcept
    ada_lifetime_bound {
  return regexp;
}

inline const std::vector<std::string>&
url_pattern_component::get_group_name_list() const noexcept ada_lifetime_bound {
  return group_name_list;
}

inline url_pattern_component_result
url_pattern_component::create_component_match_result(
    std::string_view input, const std::vector<std::string>& exec_result) {
  // Let result be a new URLPatternComponentResult.
  // Set result["input"] to input.
  // Let groups be a record<USVString, (USVString or undefined)>.
  auto result =
      url_pattern_component_result{.input = std::string(input), .groups = {}};

  // Optimization: Let's reserve the size.
  result.groups.reserve(exec_result.size() - 1);

  // Let index be 1.
  // While index is less than Get(execResult, "length"):
  for (size_t index = 1; index < exec_result.size(); index++) {
    // Let name be component’s group name list[index − 1].
    // Let value be Get(execResult, ToString(index)).
    // Set groups[name] to value.
    result.groups.insert({
        group_name_list[index - 1],
        exec_result.at(index),
    });
  }
  return result;
}

inline std::string_view url_pattern::get_protocol() const ada_lifetime_bound {
  // Return this's associated URL pattern's protocol component's pattern string.
  return protocol_component.get_pattern();
}
inline std::string_view url_pattern::get_username() const ada_lifetime_bound {
  // Return this's associated URL pattern's username component's pattern string.
  return username_component.get_pattern();
}
inline std::string_view url_pattern::get_password() const ada_lifetime_bound {
  // Return this's associated URL pattern's password component's pattern string.
  return password_component.get_pattern();
}
inline std::string_view url_pattern::get_hostname() const ada_lifetime_bound {
  // Return this's associated URL pattern's hostname component's pattern string.
  return hostname_component.get_pattern();
}
inline std::string_view url_pattern::get_port() const ada_lifetime_bound {
  // Return this's associated URL pattern's port component's pattern string.
  return port_component.get_pattern();
}
inline std::string_view url_pattern::get_pathname() const ada_lifetime_bound {
  // Return this's associated URL pattern's pathname component's pattern string.
  return pathname_component.get_pattern();
}
inline std::string_view url_pattern::get_search() const ada_lifetime_bound {
  // Return this's associated URL pattern's search component's pattern string.
  return search_component.get_pattern();
}
inline std::string_view url_pattern::get_hash() const ada_lifetime_bound {
  // Return this's associated URL pattern's hash component's pattern string.
  return hash_component.get_pattern();
}

inline bool url_pattern::ignore_case() const ada_lifetime_bound {
  return ignore_case_;
}

inline bool url_pattern::has_regexp_groups() const ada_lifetime_bound {
  // If this's associated URL pattern's has regexp groups, then return true.
  return protocol_component.has_regexp_groups() ||
         username_component.has_regexp_groups() ||
         password_component.has_regexp_groups() ||
         hostname_component.has_regexp_groups() ||
         port_component.has_regexp_groups() ||
         pathname_component.has_regexp_groups() ||
         search_component.has_regexp_groups() ||
         hash_component.has_regexp_groups();
}

inline bool url_pattern_part::is_regexp() const noexcept {
  return type == url_pattern_part_type::REGEXP;
}

namespace url_pattern_helpers {
inline void constructor_string_parser::rewind() {
  // Set parser’s token index to parser’s component start.
  token_index = component_start;
  // Set parser’s token increment to 0.
  token_increment = 0;
}

inline bool constructor_string_parser::is_hash_prefix() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index and "#".
  return is_non_special_pattern_char(token_index, "#");
}

inline bool constructor_string_parser::is_search_prefix() {
  // If result of running is a non-special pattern char given parser, parser’s
  // token index and "?" is true, then return true.
  if (is_non_special_pattern_char(token_index, "?")) {
    return true;
  }

  // If parser’s token list[parser’s token index]'s value is not "?", then
  // return false.
  if (token_list[token_index].value != "?") {
    return false;
  }

  // If previous index is less than 0, then return true.
  if (token_index == 0) return true;
  // Let previous index be parser’s token index − 1.
  auto previous_index = token_index - 1;
  // Let previous token be the result of running get a safe token given parser
  // and previous index.
  auto previous_token = get_safe_token(previous_index);
  // If any of the following are true, then return false:
  // - previous token’s type is "name".
  // - previous token’s type is "regexp".
  // - previous token’s type is "close".
  // - previous token’s type is "asterisk".
  return !(previous_token.type == token_type::NAME ||
           previous_token.type == token_type::REGEXP ||
           previous_token.type == token_type::CLOSE ||
           previous_token.type == token_type::ASTERISK);
}

inline bool constructor_string_parser::is_non_special_pattern_char(
    size_t index, std::string_view value) {
  // Let token be the result of running get a safe token given parser and index.
  auto token = get_safe_token(index);

  // If token’s value is not value, then return false.
  if (token.value != value) {
    return false;
  }

  // If any of the following are true:
  // - token’s type is "char";
  // - token’s type is "escaped-char"; or
  // - token’s type is "invalid-char",
  // - then return true.
  return token.type == token_type::CHAR ||
         token.type == token_type::ESCAPED_CHAR ||
         token.type == token_type::INVALID_CHAR ||
         token.type == token_type::INVALID_CHAR;
}

inline const Token& constructor_string_parser::get_safe_token(size_t index) {
  // If index is less than parser’s token list's size, then return parser’s
  // token list[index].
  if (index < token_list.size()) [[likely]] {
    return token_list[index];
  }

  // Assert: parser’s token list's size is greater than or equal to 1.
  ADA_ASSERT_TRUE(token_list.size() >= 1);

  // Let token be parser’s token list[last index].
  // Assert: token’s type is "end".
  ADA_ASSERT_TRUE(token_list.end()->type == token_type::END);

  // Return token.
  return *token_list.end();
}

inline bool constructor_string_parser::is_group_open() const {
  // If parser’s token list[parser’s token index]'s type is "open", then return
  // true.
  return token_list[token_index].type == token_type::OPEN;
}

inline bool constructor_string_parser::is_group_close() const {
  // If parser’s token list[parser’s token index]'s type is "close", then return
  // true.
  return token_list[token_index].type == token_type::CLOSE;
}

inline bool constructor_string_parser::next_is_authority_slashes() {
  // If the result of running is a non-special pattern char given parser,
  // parser’s token index + 1, and "/" is false, then return false.
  if (!is_non_special_pattern_char(token_index + 1, "/")) {
    return false;
  }
  // If the result of running is a non-special pattern char given parser,
  // parser’s token index + 2, and "/" is false, then return false.
  if (!is_non_special_pattern_char(token_index + 2, "/")) {
    return false;
  }
  return true;
}

inline bool constructor_string_parser::is_protocol_suffix() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index, and ":".
  return is_non_special_pattern_char(token_index, ":");
}

inline void
constructor_string_parser::compute_protocol_matches_special_scheme_flag() {
  // Let protocol string be the result of running make a component string given
  // parser.
  auto protocol_string = make_component_string();
  // Let protocol component be the result of compiling a component given
  // protocol string, canonicalize a protocol, and default options.
  auto protocol_component = url_pattern_component::compile(
      protocol_string, canonicalize_protocol,
      url_pattern_compile_component_options::DEFAULT);
  // If the result of running protocol component matches a special scheme given
  // protocol component is true, then set parser’s protocol matches a special
  // scheme flag to true.
  if (protocol_component_matches_special_scheme(
          protocol_component.get_pattern())) {
    protocol_matches_a_special_scheme_flag = true;
  }
}

inline void constructor_string_parser::change_state(State new_state,
                                                    size_t skip) {
  // If parser’s state is not "init", not "authority", and not "done", then set
  // parser’s result[parser’s state] to the result of running make a component
  // string given parser.
  if (state != State::INIT && state != State::AUTHORITY &&
      state != State::DONE) {
    auto value = make_component_string();
    // TODO: Simplify this.
    switch (state) {
      case State::PROTOCOL: {
        result.protocol = value;
        break;
      }
      case State::USERNAME: {
        result.username = value;
        break;
      }
      case State::PASSWORD: {
        result.password = value;
        break;
      }
      case State::HOSTNAME: {
        result.hostname = value;
        break;
      }
      case State::PORT: {
        result.port = value;
        break;
      }
      case State::PATHNAME: {
        result.pathname = value;
        break;
      }
      case State::SEARCH: {
        result.search = value;
        break;
      }
      case State::HASH: {
        result.hash = value;
        break;
      }
      default:
        unreachable();
    }
  } else if ((state == State::PROTOCOL || state == State::AUTHORITY ||
              state == State::USERNAME || state == State::PASSWORD ||
              state == State::HOSTNAME || state == State::PORT) &&
             (new_state == State::SEARCH || new_state == State::HASH) &&
             !result.pathname.has_value()) {
    // If parser’s state is "protocol", "authority", "username", "password",
    // "hostname", or "port"; new state is "search" or "hash"; and parser’s
    // result["pathname"] does not exist, then:
    // If parser’s protocol matches a special scheme flag is true, then set
    // parser’s result["pathname"] to "/".
    if (protocol_matches_a_special_scheme_flag) {
      result.pathname = "/";
    } else {
      // Otherwise, set parser’s result["pathname"] to the empty string.
      result.pathname = "";
    }
  } else if ((state == State::PROTOCOL || state == State::AUTHORITY ||
              state == State::USERNAME || state == State::PASSWORD ||
              state == State::HOSTNAME || state == State::PORT ||
              state == State::PATHNAME) &&
             new_state == State::HASH && !result.search.has_value()) {
    // If parser’s state is "protocol", "authority", "username", "password",
    // "hostname", "port", or "pathname"; new state is "hash"; and parser’s
    // result["search"] does not exist, then set parser’s result["search"] to
    // the empty string.
    result.search = "";
  }

  // If parser’s state is not "init" and new state is not "done", then:

  // Set parser’s state to new state.
  state = new_state;
  // Increment parser’s token index by skip.
  token_index += skip;
  // Set parser’s token increment to 0.
  token_increment = 0;
}

inline std::string_view constructor_string_parser::make_component_string() {
  // Assert: parser’s token index is less than parser’s token list's size.
  ADA_ASSERT_TRUE(token_index < token_list.size());

  // Let token be parser’s token list[parser’s token index].
  const auto token = token_list[token_index];
  // Let component start token be the result of running get a safe token given
  // parser and parser’s component start.
  const auto component_start_token = get_safe_token(component_start);
  // Let component start input index be component start token’s index.
  const auto component_start_input_index = component_start_token.index;
  // Let end index be token’s index.
  const auto end_index = token.index;
  // Return the code point substring from component start input index to end
  // index within parser’s input.
  return std::string_view(input).substr(component_start_input_index, end_index);
}

inline bool constructor_string_parser::is_an_identity_terminator() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index, and "@".
  return is_non_special_pattern_char(token_index, "@");
}

inline bool constructor_string_parser::is_pathname_start() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index, and "/".
  return is_non_special_pattern_char(token_index, "/");
}

inline bool constructor_string_parser::is_password_prefix() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index, and ":".
  return is_non_special_pattern_char(token_index, ":");
}

inline bool constructor_string_parser::is_an_ipv6_open() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index, and "[".
  return is_non_special_pattern_char(token_index, "[");
}

inline bool constructor_string_parser::is_an_ipv6_close() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index, and "]".
  return is_non_special_pattern_char(token_index, "]");
}

inline bool constructor_string_parser::is_port_prefix() {
  // Return the result of running is a non-special pattern char given parser,
  // parser’s token index, and ":".
  return is_non_special_pattern_char(token_index, ":");
}

inline void Tokenizer::get_next_code_point() {
  // Set tokenizer’s code point to the Unicode code point in tokenizer’s input
  // at the position indicated by tokenizer’s next index.
  code_point = &input[next_index];
  // Increment tokenizer’s next index by 1.
  next_index++;
}

inline void Tokenizer::seek_and_get_next_code_point(size_t new_index) {
  // Set tokenizer’s next index to index.
  next_index = new_index;
  // Run get the next code point given tokenizer.
  get_next_code_point();
}

inline void Tokenizer::add_token(token_type type, size_t next_position,
                                 size_t value_position,
                                 std::optional<size_t> value_length) {
  // This is done to merge 2 different functions into 1.
  auto default_length = value_length.value_or(next_position - value_position);

  // Let token be a new token.
  // Set token’s type to type.
  // Set token’s index to tokenizer’s index.
  // Set token’s value to the code point substring from value position with
  // length value length within tokenizer’s input.
  auto token = Token{.type = type,
                     .index = index,
                     .value = input.substr(value_position, default_length)};

  // Append token to the back of tokenizer’s token list.
  token_list.push_back(token);
  // Set tokenizer’s index to next position.
  index = next_position;
}

inline void Tokenizer::add_token_with_defaults(token_type type) {
  // Run add a token with default length given tokenizer, type, tokenizer’s next
  // index, and tokenizer’s index.
  add_token(type, next_index, index);
}

inline ada_warn_unused std::optional<url_pattern_errors>
Tokenizer::process_tokenizing_error(size_t next_position,
                                    size_t value_position) {
  // If tokenizer’s policy is "strict", then throw a TypeError.
  if (policy == token_policy::STRICT) {
    return url_pattern_errors::type_error;
  }
  // Assert: tokenizer’s policy is "lenient".
  ADA_ASSERT_TRUE(policy == token_policy::LENIENT);
  // Run add a token with default length given tokenizer, "invalid-char", next
  // position, and value position.
  add_token(token_type::INVALID_CHAR, next_position, value_position);
  return std::nullopt;
}

// @see https://urlpattern.spec.whatwg.org/#is-a-valid-name-code-point
inline bool is_valid_name_code_point(char cp, bool first) {
  // If first is true return the result of checking if code point is contained
  // in the IdentifierStart set of code points. Otherwise return the result of
  // checking if code point is contained in the IdentifierPart set of code
  // points.
  // TODO: Implement this
  (void)cp;
  (void)first;
  return true;
}

}  // namespace url_pattern_helpers

}  // namespace ada

#endif
