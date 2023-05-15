#ifndef ADA_URLPATTERN_CONSTRUCTOR_STRING_PARSER_H
#define ADA_URLPATTERN_CONSTRUCTOR_STRING_PARSER_H

#include "ada/helpers.h"

#include "ada/urlpattern_base.h"
#include "ada/urlpattern_tokenizer.h"

namespace ada::urlpattern {

enum class PARSER_STATE : uint8_t {
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
  // https://wicg.github.io/urlpattern/#parse-a-constructor-string
  static ada_really_inline void parse_contructor_string(
      std::u32string_view input);

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
  ada_really_inline token *get_safe_token(size_t &index);

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
  std::vector<token> token_list;
  size_t component_start = 0;
  size_t token_index = 0;
  size_t token_increment = 0;
  size_t group_depth = 0;
  size_t hostname_ipv6_bracket_depth = 0;
  bool protocol_matches_special_scheme = false;
  urlpattern_init result = urlpattern_init();
  PARSER_STATE state = PARSER_STATE::INIT;

 private:
  ada_really_inline constructor_string_parser(std::u32string_view input);
};
}  // namespace ada::urlpattern

#endif