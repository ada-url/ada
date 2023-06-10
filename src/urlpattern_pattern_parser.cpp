#include "ada/urlpattern_tokenizer.h"
#include "ada/urlpattern_pattern_parser.h"

#include <cassert>
#include <string>
#include <sstream>
#include <string_view>

namespace ada::urlpattern {

ada_really_inline pattern_parser::pattern_parser(
    std::function<std::u32string_view(std::u32string_view)> &encoding,
    std::u32string_view wildcard_regexp) {
  encoding_callback = encoding;

  segment_wildcard_regexp = wildcard_regexp;
}

// https://wicg.github.io/urlpattern/#escape-a-regexp-string
ada_really_inline std::u32string escape_regexp_string(
    std::u32string_view input) {
  // 1. Assert: input is an ASCII string.
  assert(ada::idna::is_ascii(input));

  std::u32string result = U"";
  size_t index = 0;
  while (index < input.size()) {
    size_t pos = input.find_first_of(U".+*?^${}()[]|/\\)");
    if (pos == std::string_view::npos) {
      result = result += input.substr(index, input.size());
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
  std::u32string_view encoded_value = encoding_callback(pending_fixed_value);

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

// https://wicg.github.io/urlpattern/#is-a-duplicate-name
ada_really_inline bool pattern_parser::is_duplicate_name(
    std::u32string_view name) {
  // 1. For each part of parser’s part list:
  // 2. If part’s name is name, then return true.
  // 3. Return false.
  return std::any_of(part_list.begin(), part_list.end(),
                     [&name](part p) { return p.name.compare(name) == 0; });
}

// https://wicg.github.io/urlpattern/#add-a-part
ada_really_inline void pattern_parser::add_part(
    std::u32string_view prefix, std::optional<token *> &name_token,
    std::optional<token *> &regexp_or_wildcard_token,
    std::u32string_view suffix, std::optional<token *> &modifier_token) {
  // 1. Let modifier be "none".
  PART_MODIFIER modifier = PART_MODIFIER::NONE;

  // 2. If modifier token is not null:
  if (modifier_token.has_value()) {
    // 1. If modifier token’s value is "?" then set modifier to "optional".
    if (modifier_token.value()->value == U"?") {
      modifier = PART_MODIFIER::OPTIONAL;
    }
    // 2. Else if modifier token’s value is "*" then set modifier to
    // "zero-or-more".
    else if (modifier_token.value()->value == U"*") {
      modifier = PART_MODIFIER::ZERO_OR_MORE;
    }
    // 3. Else if modifier token’s value is "+" then set modifier to
    // "one-or-more".
    else if (modifier_token.value()->value == U"+") {
      modifier = PART_MODIFIER::ONE_OR_MORE;
    }
  }
  // 3. If name token is null and regexp or wildcard token is null and modifier
  // is "none":
  if (!name_token.has_value() && !regexp_or_wildcard_token.has_value() &&
      modifier == PART_MODIFIER::NONE) {
    // This was a "{foo}" grouping. We add this to the pending fixed value so
    // that it will be combined with any previous or subsequent text.
    // 1. Append prefix to the end of parser’s pending fixed value.
    pending_fixed_value.append(prefix);
    return;
  }
  // 4. Run maybe add a part from the pending fixed value given parser.
  maybe_add_part_from_pendind_fixed_value();
  // 5. If name token is null and regexp or wildcard token is null:
  if (!name_token.has_value() && !regexp_or_wildcard_token.has_value()) {
    // This was a "{foo}?" grouping. The modifier means we cannot combine it
    // with other text. Therefore we add it as a part immediately.
    // 1. Assert: suffix is the empty string.
    assert(suffix.empty());
    // 2. If prefix is the empty string, then return.
    if (prefix.empty()) return;
    // 3.Let encoded value be the result of running parser’s encoding callback
    // given prefix.
    auto encoded_value = encoding_callback(prefix);

    // 4. Let part be a new part whose type is "fixed-text", value is encoded
    // value, and modifier is modifier.
    auto p = part();
    p.type = PART_TYPE::FIXED_TEXT;
    p.value = encoded_value;
    p.modifier = modifier;

    // 5. Append part to parser’s part list.
    part_list.push_back(p);
    return;
  }

  // 6. Let regexp value be the empty string.
  std::u32string regexp_value{};

  // Next, we convert the regexp or wildcard token into a regular expression.

  // 7. If regexp or wildcard token is null, then set regexp value to parser’s
  // segment wildcard regexp.
  if (!regexp_or_wildcard_token.has_value()) {
    regexp_value = segment_wildcard_regexp;
  }
  // 8. Else if regexp or wildcard token’s type is "asterisk", then set regexp
  // value to the full wildcard regexp value.
  else if (regexp_or_wildcard_token.value()->type == TOKEN_TYPE::ASTERISK) {
    regexp_value = full_wildcard_regexp_value;
  }
  // 9. Else set regexp value to regexp or wildcard token’s value.
  else {
    regexp_value = regexp_or_wildcard_token.value()->value;
  }
  // 10. Let type be "regexp".
  auto type = PART_TYPE::REGEXP;
  // Next, we convert regexp value into a part type. We make sure to go to a
  // regular expression first so that an equivalent "regexp" token will be
  // treated the same as a "name" or "asterisk" token.

  // 11. If regexp value is parser’s segment wildcard regexp:
  if (regexp_value == segment_wildcard_regexp) {
    // 1. Set type to "segment-wildcard".
    type = PART_TYPE::SEGMENT_WILDCARD;
    // 2. Set regexp value to the empty string.
    regexp_value.clear();
  }
  // 12. Else if regexp value is the full wildcard regexp value:
  else if (regexp_value == full_wildcard_regexp_value) {
    // 1. Set type to "full-wildcard".
    type = PART_TYPE::FULL_WILDCARD;
    // 2. Set regexp value to the empty string.
    regexp_value.clear();
  }
  // 13. Let name be the empty string.
  std::u32string name{};
  // Next, we determine the part name. This can be explicitly provided by a
  // "name" token or be automatically assigned.

  // 14. If name token is not null, then set name to name token’s value.
  if (name_token.has_value()) {
    name = name_token.value()->value;
  }
  // 15. Else if regexp or wildcard token is not null:
  else if (regexp_or_wildcard_token.has_value()) {
    // 1. Set name to parser’s next numeric name.
    // TODO: Needs a huge improvement
    std::stringstream ss{};
    ss << next_numeric_name;
    for (char c : ss.str()) {
      name += c;
    }
    // 2. Increment parser’s next numeric name by 1.
    ++next_numeric_name;
  }
  // 16 If the result of running is a duplicate name given parser and name is
  // true, then throw a TypeError.
  if (is_duplicate_name(name)) {
    throw std::bad_typeid();
  }
}

// https://wicg.github.io/urlpattern/#try-to-consume-a-modifier-tokenssss
ada_really_inline std::optional<token *>
pattern_parser::try_to_consume_modifier_token() {
  // 1. Let token be the result of running try to consume a token given parser
  // and "other-modifier".
  std::optional<token *> t = try_to_consume_token(TOKEN_TYPE::OTHER_MODIFIER);

  // 2. If token is not null, then return token.
  if (t.has_value()) {
    return t;
  }

  // 3. Set token to the result of running try to consume a token given parser
  // and "asterisk".
  t = try_to_consume_token(TOKEN_TYPE::ASTERISK);
  return t;
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
    std::function<std::u32string_view(std::u32string_view)>
        &encoding_callback) {
  // 1. Let parser be a new pattern parser whose encoding callback is encoding
  // callback and segment wildcard regexp is the result of running generate a
  // segment wildcard regexp given options.
  std::u32string seg_wildcard_regexp =
      generate_segment_wildcard_regexp(options);
  auto p = pattern_parser(encoding_callback, seg_wildcard_regexp);

  // 1. Set parser’s token list to the result of running tokenize given input
  // and "strict".
  p.token_list = tokenize(input, POLICY::STRICT);

  // 3. While parser’s index is less than parser’s token list's size:
  while (p.index < p.token_list.size()) {
    // 1. Let char token be the result of running try to consume a token given
    // parser and "char".
    std::optional<token *> char_token =
        p.try_to_consume_token(TOKEN_TYPE::CHAR);

    // 2. Let name token be the result of running try to consume a token given
    // parser and "name".
    std::optional<token *> name_token =
        p.try_to_consume_token(TOKEN_TYPE::NAME);

    // 2. Let regexp or wildcard token be the result of running try to consume a
    // regexp or wildcard token given parser and name token.
    std::optional<token *> regexp_or_wildcard =
        p.try_to_consume_regexp_or_wildcard_token(name_token);

    // 3. If name token is not null or regexp or wildcard token is not null:
    if (name_token.has_value() || regexp_or_wildcard.has_value()) {
      // If there is a matching group, we need to add the part immediately.

      // 1. Let prefix be the empty string.
      std::u32string prefix{};

      // 2. If char token is not null then set prefix to char token’s value.
      if (char_token.has_value()) {
        prefix = char_token.value()->value;
      }

      // 3. If prefix is not the empty string and not options’s prefix code
      // point:
      if (!prefix.empty() && prefix != options.prefix) {
        // 1. Append prefix to the end of parser’s pending fixed value.
        p.pending_fixed_value.append(prefix);
        // 2. Set prefix to the empty string.
        prefix.clear();
      }

      // 4. Run maybe add a part from the pending fixed value given parser.
      p.maybe_add_part_from_pendind_fixed_value();

      // 5. Let modifier token be the result of running try to consume a
      // modifier token given parser.
      std::optional<token *> modifier_token = p.try_to_consume_modifier_token();

      // 6. Run add a part given parser, prefix, name token, regexp or wildcard
      // token, the empty string, and modifier token.
      p.ad
    }
  }

  return p.part_list;
}

}  // namespace ada::urlpattern