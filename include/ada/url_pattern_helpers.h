/**
 * @file url_pattern_helpers.h
 * @brief Declaration for the URLPattern helpers.
 */
#ifndef ADA_URL_PATTERN_HELPERS_H
#define ADA_URL_PATTERN_HELPERS_H

#include "ada/expected.h"
#include "ada/implementation.h"
#include "ada/url_pattern_helpers.h"

#include <string>
#include <tuple>
#include <vector>

namespace ada::url_pattern_helpers {

// @see https://urlpattern.spec.whatwg.org/#token
enum class token_type : uint8_t {
  INVALID_CHAR,    // 0
  OPEN,            // 1
  CLOSE,           // 2
  REGEXP,          // 3
  NAME,            // 4
  CHAR,            // 5
  ESCAPED_CHAR,    // 6
  OTHER_MODIFIER,  // 7
  ASTERISK,        // 8
  END,             // 9
};

std::string to_string(token_type type);

// @see https://urlpattern.spec.whatwg.org/#tokenize-policy
enum class token_policy {
  STRICT,
  LENIENT,
};

// @see https://urlpattern.spec.whatwg.org/#tokens
class Token {
 public:
  Token(token_type _type, size_t _index, std::string&& _value)
      : type(_type), index(_index), value(std::move(_value)) {}

  // A token has an associated type, a string, initially "invalid-char".
  token_type type = token_type::INVALID_CHAR;

  // A token has an associated index, a number, initially 0. It is the position
  // of the first code point in the pattern string represented by the token.
  size_t index = 0;

  // A token has an associated value, a string, initially the empty string. It
  // contains the code points from the pattern string represented by the token.
  std::string value{};
};


// @see https://urlpattern.spec.whatwg.org/#tokenizer
class Tokenizer {
 public:
  explicit Tokenizer(std::string_view new_input, token_policy new_policy)
      : input(new_input), policy(new_policy) {}

  // @see https://urlpattern.spec.whatwg.org/#get-the-next-code-point
  void get_next_code_point();

  // @see https://urlpattern.spec.whatwg.org/#seek-and-get-the-next-code-point
  void seek_and_get_next_code_point(size_t index);

  // @see https://urlpattern.spec.whatwg.org/#add-a-token

  void add_token(token_type type, size_t next_position, size_t value_position,
                 size_t value_length);

  // @see https://urlpattern.spec.whatwg.org/#add-a-token-with-default-length
  void add_token_with_default_length(token_type type, size_t next_position,
                                     size_t value_position);

  // @see
  // https://urlpattern.spec.whatwg.org/#add-a-token-with-default-position-and-length
  void add_token_with_defaults(token_type type);

  // @see https://urlpattern.spec.whatwg.org/#process-a-tokenizing-error
  std::optional<errors> process_tokenizing_error(
      size_t next_position, size_t value_position) ada_warn_unused;

  // has an associated input, a pattern string, initially the empty string.
  std::string input;
  // has an associated policy, a tokenize policy, initially "strict".
  token_policy policy;
  // has an associated token list, a token list, initially an empty list.
  std::vector<Token> token_list{};
  // has an associated index, a number, initially 0.
  size_t index = 0;
  // has an associated next index, a number, initially 0.
  size_t next_index = 0;
  // has an associated code point, a Unicode code point, initially null.
  char32_t code_point{};
};

// @see https://urlpattern.spec.whatwg.org/#tokenize
tl::expected<std::vector<Token>, errors> tokenize(std::string_view input,
                                                  token_policy policy);
}  // namespace ada::url_pattern_helpers
#endif
