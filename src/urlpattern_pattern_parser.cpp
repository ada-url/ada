#include "ada/urlpattern_tokenizer.h"
#include "ada/urlpattern_pattern_parser.h"

#include <cassert>

namespace ada::urlpattern {

ada_really_inline pattern_parser::pattern_parser(
    std::function<std::string_view(std::u32string_view)> &encoding,
    std::u32string_view wildcard_regexp) {
  encoding_callback = encoding;

  segment_wildcard_regexp = wildcard_regexp;
}

// https://wicg.github.io/urlpattern/#escape-a-regexp-string
ada_really_inline std::u32string escape_regexp_string(
    std::u32string_view input) {
  assert(ada::idna::is_ascii(input));

  //  // TODO: make it cheaper
  //  size_t u8input_size =
  //      ada::idna::utf8_length_from_utf32(input.data(), input.size());
  //  std::string final_u8input(u8input_size, '\0');
  //  ada::idna::utf32_to_utf8(input.data(), input.size(),
  //  final_u8input.data());

  std::u32string result = U"";
  size_t index = 0;
  while (index < input.size()) {
    size_t pos = input.find_first_of(U".+*?^${}()[]|/\\)");
    if (pos == std::string_view::npos) {
      result += input.substr(index, input.size());
      break;
    }
    result.append(input.substr(index, pos)).append(U"\\");
    result += input[pos];
    index = pos + 1;
  }
  return result;
}

// https://wicg.github.io/urlpattern/#maybe-add-a-part-from-the-pending-fixed-value
ada_really_inline void
pattern_parser::maybe_add_part_from_pendind_fixed_value() {
  // If parser’s pending fixed value is the empty string, then return.
  if (pending_fixed_value.empty()) {
    return;
  }

  // Let encoded value be the result of running parser’s encoding callback given
  // parser’s pending fixed value.
  std::string_view encoded_value = encoding_callback(pending_fixed_value);

  // Set parser’s pending fixed value to the empty strin
  pending_fixed_value.clear();
  // Let part be a new part whose type is "fixed-text", value is encoded value,
  // and modifier is "none".
  auto p = part();
  p.type = PART_TYPE::FIXED_TEXT;
  p.modifier = PART_MODIFIER::NONE;
  p.value = encoded_value;

  // Append part to parser’s part list.
  part_list.push_back(p);
}

// https://wicg.github.io/urlpattern/#generate-a-segment-wildcard-regexp
ada_really_inline std::u32string generate_segment_wildcard_regexp(
    u32urlpattern_options &options) {
  // Let result be "[^".
  std::u32string result = U"[^";

  // Append the result of running escape a regexp string given options’s
  // delimiter code point to the end of result.
  result.append(escape_regexp_string(options.delimiter)).append(U"]+?");

  // Append "]+?" to the end of result.
  return result;
}

ada_really_inline std::optional<token *> pattern_parser::try_to_consume_token(
    TOKEN_TYPE type) {
  // Assert: parser’s index is less than parser’s token list size.
  assert(index < token_list.size());
  // Let next token be parser’s token list[parser’s index].
  token *next_token = &token_list[index];

  // If next token’s type is not type return null.
  if (next_token->type != type) {
    return std::nullopt;
  }

  // Increment parser’s index by 1.
  ++index;
  return next_token;
}

ada_really_inline std::optional<token *>
pattern_parser::try_to_consume_regexp_or_wildcard_token(
    std::optional<token *> &name_token) {
  // Let token be the result of running try to consume a token given parser and
  // "regexp".
  std::optional<token *> regexp_or_wildcard =
      try_to_consume_token(TOKEN_TYPE::REGEXP);

  // If name token is null and token is null, then set token to the result of
  // running try to consume a token given parser and "asterisk".
  if (!name_token.has_value() && !regexp_or_wildcard.has_value()) {
    regexp_or_wildcard = try_to_consume_token(TOKEN_TYPE::ASTERISK);
  }

  return regexp_or_wildcard;
}

// https://wicg.github.io/urlpattern/#parse-a-pattern-string
std::vector<part> parse_pattern_string(
    std::u32string_view input, u32urlpattern_options &options,
    std::function<std::string_view(std::u32string_view)> &encoding) {
  // Let parser be a new pattern parser whose encoding callback is encoding
  // callback and segment wildcard regexp is the result of running generate a
  // segment wildcard regexp given options.

  std::u32string seg_wildcard_regexp =
      generate_segment_wildcard_regexp(options);
  auto p = pattern_parser(encoding, seg_wildcard_regexp);

  // Set parser’s token list to the result of running tokenize given input and
  // "strict".
  p.token_list = tokenize(input, POLICY::STRICT);

  // While parser’s index is less than parser’s token list's size:
  while (p.index < p.token_list.size()) {
    // Let char token be the result of running try to consume a token given
    // parser and "char".
    std::optional<token *> char_token =
        p.try_to_consume_token(TOKEN_TYPE::CHAR);

    // Let name token be the result of running try to consume a token given
    // parser and "name".
    std::optional<token *> name_token =
        p.try_to_consume_token(TOKEN_TYPE::NAME);

    // Let regexp or wildcard token be the result of running try to consume a
    // regexp or wildcard token given parser and name token.
    std::optional<token *> regexp_or_wildcard =
        p.try_to_consume_regexp_or_wildcard_token(name_token);

    // If name token is not null or regexp or wildcard token is not null:
    if (name_token.has_value() || regexp_or_wildcard.has_value()) {
      // If there is a matching group, we need to add the part immediately.
      // Let prefix be the empty string.
      // If char token is not null then set prefix to char token’s value.
      std::u32string prefix{};
      //      if (char_token.has_value()) {
      //        prefix.append(input.substr(char_token.value()->value_start,
      //                                   char_token.value()->value_end + 1));
      //      }

      // If prefix is not the empty string and not options’s prefix code point:
      if (!prefix.empty() && prefix != options.prefix) {
        // Append prefix to the end of parser’s pending fixed value.
        p.pending_fixed_value.append(prefix);
        // Set prefix to the empty string.
        prefix.clear();
      }

      // Run maybe add a part from the pending fixed value given parser.
      p.maybe_add_part_from_pendind_fixed_value();
    }
  }

  return p.part_list;
}

}  // namespace ada::urlpattern