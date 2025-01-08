/**
 * @file url_pattern_helpers-inl.h
 * @brief Declaration for the URLPattern helpers.
 */
#ifndef ADA_URL_PATTERN_HELPERS_INL_H
#define ADA_URL_PATTERN_HELPERS_INL_H

#include "ada/common_defs.h"
#include "ada/expected.h"
#include "ada/url_pattern.h"
#include "ada/url_pattern_helpers.h"

namespace ada::url_pattern_helpers {
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
  code_point = input[next_index];
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
  ADA_ASSERT_TRUE(next_position >= value_position);
  // This is done to merge 2 different functions into 1.
  auto computed_length = value_length.value_or(next_position - value_position);

  // Let token be a new token.
  // Set token’s type to type.
  // Set token’s index to tokenizer’s index.
  // Set token’s value to the code point substring from value position with
  // length value length within tokenizer’s input.
  auto token = Token{.type = type,
                     .index = index,
                     .value = input.substr(value_position, computed_length)};

  // Append token to the back of tokenizer’s token list.
  token_list.push_back(std::move(token));
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

template <url_pattern_encoding_callback F>
Token* url_pattern_parser<F>::try_consume_modifier_token() {
  // Let token be the result of running try to consume a token given parser and
  // "other-modifier".
  auto token = try_consume_token(token_type::OTHER_MODIFIER);
  // If token is not null, then return token.
  if (token) return token;
  // Set token to the result of running try to consume a token given parser and
  // "asterisk".
  token = try_consume_token(token_type::ASTERISK);
  // Return token.
  return token;
}

template <url_pattern_encoding_callback F>
Token* url_pattern_parser<F>::try_consume_regexp_or_wildcard_token(
    Token* name_token) {
  // Let token be the result of running try to consume a token given parser and
  // "regexp".
  auto token = try_consume_token(token_type::REGEXP);
  // If name token is null and token is null, then set token to the result of
  // running try to consume a token given parser and "asterisk".
  if (!name_token && !token) {
    token = try_consume_token(token_type::ASTERISK);
  }
  // Return token.
  return token;
}

template <url_pattern_encoding_callback F>
Token* url_pattern_parser<F>::try_consume_token(token_type type) {
  // Assert: parser’s index is less than parser’s token list size.
  ADA_ASSERT_TRUE(index < tokens.size());
  // Let next token be parser’s token list[parser’s index].
  auto& next_token = tokens.at(index);
  // If next token’s type is not type return null.
  if (next_token.type != type) return nullptr;
  // Increase parser’s index by 1.
  index++;
  // Return next token.
  return &next_token;
}

template <url_pattern_encoding_callback F>
std::string url_pattern_parser<F>::consume_text() {
  // Let result be the empty string.
  std::string result{};
  // While true:
  while (true) {
    // Let token be the result of running try to consume a token given parser
    // and "char".
    auto token = try_consume_token(token_type::CHAR);
    // If token is null, then set token to the result of running try to consume
    // a token given parser and "escaped-char".
    if (!token) token = try_consume_token(token_type::ESCAPED_CHAR);
    // If token is null, then break.
    if (!token) break;
    // Append token’s value to the end of result.
    result.append(token->value);
  }
  // Return result.
  return result;
}

template <url_pattern_encoding_callback F>
tl::expected<Token, url_pattern_errors>
url_pattern_parser<F>::consume_required_token(token_type type) {
  // Let result be the result of running try to consume a token given parser and
  // type.
  auto result = try_consume_token(type);
  // If result is null, then throw a TypeError.
  if (!result) {
    return tl::unexpected(url_pattern_errors::type_error);
  }
  return *result;
}

template <url_pattern_encoding_callback F>
std::optional<url_pattern_errors>
url_pattern_parser<F>::maybe_add_part_from_the_pending_fixed_value() {
  // If parser’s pending fixed value is the empty string, then return.
  if (pending_fixed_value.empty()) return std::nullopt;
  // Let encoded value be the result of running parser’s encoding callback given
  // parser’s pending fixed value.
  auto encoded_value = encoding_callback(pending_fixed_value);
  if (!encoded_value) {
    return encoded_value.error();
  }
  // Set parser’s pending fixed value to the empty string.
  pending_fixed_value.clear();
  // Let part be a new part whose type is "fixed-text", value is encoded value,
  // and modifier is "none".
  url_pattern_part part{.type = url_pattern_part_type::FIXED_TEXT,
                        .value = std::move(*encoded_value),
                        .modifier = url_pattern_part_modifier::NONE};
  // Append part to parser’s part list.
  parts.push_back(std::move(part));
  return std::nullopt;
}

template <url_pattern_encoding_callback F>
std::optional<url_pattern_errors> url_pattern_parser<F>::add_part(
    std::string_view prefix, Token* name_token, Token* regexp_or_wildcard_token,
    std::string_view suffix, Token* modifier_token) {
  // Let modifier be "none".
  auto modifier = url_pattern_part_modifier::NONE;
  // If modifier token is not null:
  if (modifier_token) {
    // If modifier token’s value is "?" then set modifier to "optional".
    if (modifier_token->value == "?") {
      modifier = url_pattern_part_modifier::OPTIONAL;
    } else if (modifier_token->value == "*") {
      // Otherwise if modifier token’s value is "*" then set modifier to
      // "zero-or-more".
      modifier = url_pattern_part_modifier::ZERO_OR_MORE;
    } else if (modifier_token->value == "+") {
      // Otherwise if modifier token’s value is "+" then set modifier to
      // "one-or-more".
      modifier = url_pattern_part_modifier::ONE_OR_MORE;
    }
    // If name token is null and regexp or wildcard token is null and modifier
    // is "none":
    if (!name_token && !regexp_or_wildcard_token &&
        modifier == url_pattern_part_modifier::NONE) {
      // Append prefix to the end of parser’s pending fixed value.
      pending_fixed_value.append(prefix);
      return std::nullopt;
    }
    // Run maybe add a part from the pending fixed value given parser.
    if (auto error = maybe_add_part_from_the_pending_fixed_value()) {
      return *error;
    }
    // If name token is null and regexp or wildcard token is null:
    if (!name_token && !regexp_or_wildcard_token) {
      // Assert: suffix is the empty string.
      ADA_ASSERT_TRUE(suffix.empty());
      // If prefix is the empty string, then return.
      if (prefix.empty()) return std::nullopt;
      // Let encoded value be the result of running parser’s encoding callback
      // given prefix.
      auto encoded_value = encoding_callback(prefix);
      if (!encoded_value) {
        return encoded_value.error();
      }
      // Let part be a new part whose type is "fixed-text", value is encoded
      // value, and modifier is modifier.
      url_pattern_part part{.type = url_pattern_part_type::FIXED_TEXT,
                            .value = std::move(*encoded_value),
                            .modifier = modifier};
      // Append part to parser’s part list.
      parts.push_back(std::move(part));
      return std::nullopt;
    }
    // Let regexp value be the empty string.
    std::string regexp_value{};
    // If regexp or wildcard token is null, then set regexp value to parser’s
    // segment wildcard regexp.
    if (!regexp_or_wildcard_token) {
      regexp_value = segment_wildcard_regexp;
    } else if (regexp_or_wildcard_token->type == token_type::ASTERISK) {
      // Otherwise if regexp or wildcard token’s type is "asterisk", then set
      // regexp value to the full wildcard regexp value.
      regexp_value = ".*";
    } else {
      // Otherwise set regexp value to regexp or wildcard token’s value.
      regexp_value = regexp_or_wildcard_token->value;
    }
    // Let type be "regexp".
    auto type = url_pattern_part_type::REGEXP;
    // If regexp value is parser’s segment wildcard regexp:
    if (regexp_value == segment_wildcard_regexp) {
      // Set type to "segment-wildcard".
      type = url_pattern_part_type::SEGMENT_WILDCARD;
      // Set regexp value to the empty string.
      regexp_value.clear();
    } else if (regexp_value == ".*") {
      // Otherwise if regexp value is the full wildcard regexp value:
      // Set type to "full-wildcard".
      type = url_pattern_part_type::FULL_WILDCARD;
      // Set regexp value to the empty string.
      regexp_value.clear();
    }
    // Let name be the empty string.
    std::string name{};
    // If name token is not null, then set name to name token’s value.
    if (name_token) {
      name = name_token->value;
    } else if (regexp_or_wildcard_token) {
      // Otherwise if regexp or wildcard token is not null:
      // Set name to parser’s next numeric name, serialized.
      // TODO: Make sure this is correct.
      name = std::to_string(next_numeric_name);
      // Increment parser’s next numeric name by 1.
      next_numeric_name++;
    }
    // If the result of running is a duplicate name given parser and name is
    // true, then throw a TypeError.
    if (is_duplicate_name(name)) {
      return url_pattern_errors::type_error;
    }
    // Let encoded prefix be the result of running parser’s encoding callback
    // given prefix.
    auto encoded_prefix = encoding_callback(prefix);
    if (!encoded_prefix) return encoded_prefix.error();
    // Let encoded suffix be the result of running parser’s encoding callback
    // given suffix.
    auto encoded_suffix = encoding_callback(suffix);
    if (!encoded_suffix) return encoded_suffix.error();
    // Let part be a new part whose type is type, value is regexp value,
    // modifier is modifier, name is name, prefix is encoded prefix, and suffix
    // is encoded suffix.
    auto part = url_pattern_part{.type = type,
                                 .value = std::move(regexp_value),
                                 .modifier = modifier,
                                 .prefix = std::move(*encoded_prefix),
                                 .suffix = std::move(*encoded_suffix)};
    // Append part to parser’s part list.
    parts.push_back(std::move(part));
  }
  return std::nullopt;
}

template <url_pattern_encoding_callback F>
bool url_pattern_parser<F>::is_duplicate_name(std::string_view name) {
  // For each part of parser’s part list:
  // If part’s name is name, then return true.
  return std::ranges::any_of(
      parts, [&name](const auto& part) { return part.name == name; });
}

}  // namespace ada::url_pattern_helpers

#endif
