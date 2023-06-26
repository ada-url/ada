#ifndef ADA_URLPATTERN_PATTERN_PARSER_H
#define ADA_URLPATTERN_PATTERN_PARSER_H

#include "ada/helpers.h"

#include "ada/urlpattern_base.h"
#include "ada/urlpattern_tokenizer.h"

#include <string>
#include <vector>

namespace ada::urlpattern {

enum class PART_TYPE : uint8_t {
  FIXED_TEXT,
  REGEXP,
  SEGMENT_WILDCARD,
  FULL_WILDCARD
};
enum class PART_MODIFIER : uint8_t {
  NONE,
  OPTIONAL,
  ZERO_OR_MORE,
  ONE_OR_MORE
};

// https://wicg.github.io/urlpattern/#part
struct part {
  PART_TYPE type;
  PART_MODIFIER modifier;
  std::u32string_view value;
  std::u32string_view name{};
  std::u32string_view prefix{};
  std::u32string_view suffix{};
};

// https://wicg.github.io/urlpattern/#pattern-parser
struct pattern_parser {
  ada_really_inline pattern_parser(
      std::function<std::u32string_view(std::u32string_view)> &encoding,
      std::u32string_view wildcard_regexp);

  // https://wicg.github.io/urlpattern/#try-to-consume-a-token
  ada_really_inline std::optional<token *> try_to_consume_token(
      TOKEN_TYPE type);

  // https://wicg.github.io/urlpattern/#try-to-consume-a-modifier-tokenssss
  ada_really_inline std::optional<token *> try_to_consume_modifier_token();

  // https://wicg.github.io/urlpattern/#try-to-consume-a-regexp-or-wildcard-token
  ada_really_inline std::optional<token *>
  try_to_consume_regexp_or_wildcard_token(std::optional<token *> &name_token);

  // https://wicg.github.io/urlpattern/#maybe-add-a-part-from-the-pending-fixed-value
  ada_really_inline void maybe_add_part_from_pendind_fixed_value();

  // https://wicg.github.io/urlpattern/#add-a-part
  ada_really_inline void add_part(
      std::u32string_view prefix, std::optional<token *> &name_token,
      std::optional<token *> &regexp_or_wildcard_token,
      std::u32string_view suffix, std::optional<token *> &modifier_token);

  // https://wicg.github.io/urlpattern/#is-a-duplicate-name
  ada_really_inline bool is_duplicate_name(std::u32string_view name);

  std::vector<token> token_list;
  std::function<std::u32string_view(std::u32string_view)> encoding_callback;
  std::u32string segment_wildcard_regexp;
  std::u32string pending_fixed_value{};
  std::u32string full_wildcard_regexp_value = U".*";
  size_t index = 0;
  size_t next_numeric_name = 0;
  std::vector<part> part_list{};
};

// https://wicg.github.io/urlpattern/#parse-a-pattern-string
std::vector<part> parse_pattern_string(
    std::u32string_view input, u32urlpattern_options &options,
    std::function<std::string_view(std::u32string_view)> &encoding);

}  // namespace ada::urlpattern

#endif