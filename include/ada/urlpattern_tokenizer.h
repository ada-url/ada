#ifndef ADA_URLPATTERN_TOKENIZER_H
#define ADA_URLPATTERN_TOKENIZER_H

#include "ada/helpers.h"

#include <vector>
#include <string_view>
#include <utility>

namespace ada::urlpattern {

enum class TOKEN_TYPE : uint8_t {
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

struct token {
  TOKEN_TYPE type;
  size_t value_start;
  size_t value_end;
};

enum class POLICY : uint8_t { STRICT, LENIENT };

// https://wicg.github.io/urlpattern/#tokenizer
struct tokenizer {
  std::u32string_view input{};
  POLICY policy = POLICY::STRICT;
  std::vector<token> token_list{};
  size_t index = 0;
  size_t next_index = 0;
  char32_t code_point;

  // https://wicg.github.io/urlpattern/#seek-and-get-the-next-code-point
  ada_really_inline void seek_and_get_next_code_point();

  // https://wicg.github.io/urlpattern/#get-the-next-code-point
  ada_really_inline void get_next_code_point();

  // https://wicg.github.io/urlpattern/#add-a-token
  ada_really_inline void add_token(TOKEN_TYPE type, size_t next_pos,
                                   size_t value_start, size_t value_end);

  // https://wicg.github.io/urlpattern/#process-a-tokenizing-error
  ada_really_inline void process_tokenizing_error(std::string_view msg,
                                                  size_t value_start,
                                                  size_t value_end);
};

/**
 * Tokenize is a step in the approach used by the URLPattern API for parsing
 * patterns.
 * @see https://wicg.github.io/urlpattern/#tokenize and
 * https://wicg.github.io/urlpattern/#parsing-patterns
 */
std::vector<token> tokenize(std::u32string_view input, POLICY policy);

}  // namespace ada::urlpattern

#endif