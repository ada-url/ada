/**
 * @file url_pattern_helpers.h
 * @brief Declaration for the URLPattern helpers.
 */
#ifndef ADA_URL_PATTERN_HELPERS_H
#define ADA_URL_PATTERN_HELPERS_H

#include "ada/expected.h"
#include "ada/common_defs.h"
#include "ada/url_pattern.h"

#include <string>
#include <tuple>
#include <vector>

namespace ada {
enum class errors : uint8_t;
}

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

#ifdef ADA_TESTING
std::string to_string(token_type type);
#endif  // ADA_TESTING

// @see https://urlpattern.spec.whatwg.org/#tokenize-policy
enum class token_policy {
  strict,
  lenient,
};

// @see https://urlpattern.spec.whatwg.org/#tokens
class token {
 public:
  token(token_type _type, size_t _index, std::string&& _value)
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

// @see https://urlpattern.spec.whatwg.org/#pattern-parser
template <url_pattern_encoding_callback F>
class url_pattern_parser {
 public:
  url_pattern_parser(F& encoding_callback_,
                     std::string_view segment_wildcard_regexp_)
      : encoding_callback(encoding_callback_),
        segment_wildcard_regexp(segment_wildcard_regexp_) {}

  bool can_continue() const { return index < tokens.size(); }

  // @see https://urlpattern.spec.whatwg.org/#try-to-consume-a-token
  token* try_consume_token(token_type type);
  // @see https://urlpattern.spec.whatwg.org/#try-to-consume-a-modifier-token
  token* try_consume_modifier_token();
  // @see
  // https://urlpattern.spec.whatwg.org/#try-to-consume-a-regexp-or-wildcard-token
  token* try_consume_regexp_or_wildcard_token(const token* name_token);
  // @see https://urlpattern.spec.whatwg.org/#consume-text
  std::string consume_text();
  // @see https://urlpattern.spec.whatwg.org/#consume-a-required-token
  bool consume_required_token(token_type type);
  // @see
  // https://urlpattern.spec.whatwg.org/#maybe-add-a-part-from-the-pending-fixed-value
  std::optional<errors> maybe_add_part_from_the_pending_fixed_value()
      ada_warn_unused;
  // @see https://urlpattern.spec.whatwg.org/#add-a-part
  std::optional<errors> add_part(std::string_view prefix, token* name_token,
                                 token* regexp_or_wildcard_token,
                                 std::string_view suyffix,
                                 token* modifier_token) ada_warn_unused;

  std::vector<token> tokens{};
  F& encoding_callback;
  std::string segment_wildcard_regexp;
  std::vector<url_pattern_part> parts{};
  std::string pending_fixed_value{};
  size_t index = 0;
  size_t next_numeric_name = 0;
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

  friend tl::expected<std::vector<token>, errors> tokenize(
      std::string_view input, token_policy policy);

 private:
  // has an associated input, a pattern string, initially the empty string.
  std::string input;
  // has an associated policy, a tokenize policy, initially "strict".
  token_policy policy;
  // has an associated token list, a token list, initially an empty list.
  std::vector<token> token_list{};
  // has an associated index, a number, initially 0.
  size_t index = 0;
  // has an associated next index, a number, initially 0.
  size_t next_index = 0;
  // has an associated code point, a Unicode code point, initially null.
  char32_t code_point{};
};

// @see https://urlpattern.spec.whatwg.org/#constructor-string-parser
template <url_pattern_regex::regex_concept regex_provider>
struct constructor_string_parser {
  explicit constructor_string_parser(std::string_view new_input,
                                     std::vector<token>&& new_token_list)
      : input(new_input), token_list(std::move(new_token_list)) {}

  // @see https://urlpattern.spec.whatwg.org/#rewind
  void rewind();

  // @see https://urlpattern.spec.whatwg.org/#is-a-hash-prefix
  bool is_hash_prefix();

  // @see https://urlpattern.spec.whatwg.org/#is-a-search-prefix
  bool is_search_prefix();

  // @see https://urlpattern.spec.whatwg.org/#parse-a-constructor-string
  static tl::expected<url_pattern_init, errors> parse(std::string_view input);

  // @see https://urlpattern.spec.whatwg.org/#constructor-string-parser-state
  enum class State {
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
    DONE,
  };

  // @see https://urlpattern.spec.whatwg.org/#change-state
  void change_state(State state, size_t skip);

  // @see https://urlpattern.spec.whatwg.org/#is-a-group-open
  bool is_group_open() const;

  // @see https://urlpattern.spec.whatwg.org/#is-a-group-close
  bool is_group_close() const;

  // @see https://urlpattern.spec.whatwg.org/#is-a-protocol-suffix
  bool is_protocol_suffix() const;

  // @see
  // https://urlpattern.spec.whatwg.org/#compute-protocol-matches-a-special-scheme-flag
  std::optional<errors> compute_protocol_matches_special_scheme_flag();

  // @see https://urlpattern.spec.whatwg.org/#next-is-authority-slashes
  bool next_is_authority_slashes() const;

  // @see https://urlpattern.spec.whatwg.org/#is-an-identity-terminator
  bool is_an_identity_terminator() const;

  // @see https://urlpattern.spec.whatwg.org/#is-a-pathname-start
  bool is_pathname_start() const;

  // @see https://urlpattern.spec.whatwg.org/#is-a-password-prefix
  bool is_password_prefix() const;

  // @see https://urlpattern.spec.whatwg.org/#is-an-ipv6-open
  bool is_an_ipv6_open() const;

  // @see https://urlpattern.spec.whatwg.org/#is-an-ipv6-close
  bool is_an_ipv6_close() const;

  // @see https://urlpattern.spec.whatwg.org/#is-a-port-prefix
  bool is_port_prefix() const;

 private:
  // @see https://urlpattern.spec.whatwg.org/#is-a-non-special-pattern-char
  bool is_non_special_pattern_char(size_t index, std::string_view value) const;

  // @see https://urlpattern.spec.whatwg.org/#get-a-safe-token
  const token* get_safe_token(size_t index) const;

  // @see https://urlpattern.spec.whatwg.org/#make-a-component-string
  std::string make_component_string();
  // has an associated input, a string, which must be set upon creation.
  std::string input;
  // has an associated token list, a token list, which must be set upon
  // creation.
  std::vector<token> token_list;
  // has an associated result, a URLPatternInit, initially set to a new
  // URLPatternInit.
  url_pattern_init result{};
  // has an associated component start, a number, initially set to 0.
  size_t component_start = 0;
  // has an associated token index, a number, initially set to 0.
  size_t token_index = 0;
  // has an associated token increment, a number, initially set to 1.
  size_t token_increment = 1;
  // has an associated group depth, a number, initially set to 0.
  size_t group_depth = 0;
  // has an associated hostname IPv6 bracket depth, a number, initially set to
  // 0.
  size_t hostname_ipv6_bracket_depth = 0;
  // has an associated protocol matches a special scheme flag, a boolean,
  // initially set to false.
  bool protocol_matches_a_special_scheme_flag = false;
  // has an associated state, a string, initially set to "init".
  State state = State::INIT;
};

// @see https://urlpattern.spec.whatwg.org/#canonicalize-a-protocol
tl::expected<std::string, errors> canonicalize_protocol(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-username
tl::expected<std::string, errors> canonicalize_username(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-password
tl::expected<std::string, errors> canonicalize_password(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-password
tl::expected<std::string, errors> canonicalize_hostname(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-an-ipv6-hostname
tl::expected<std::string, errors> canonicalize_ipv6_hostname(
    std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-port
tl::expected<std::string, errors> canonicalize_port(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-port
tl::expected<std::string, errors> canonicalize_port_with_protocol(
    std::string_view input, std::string_view protocol);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-pathname
tl::expected<std::string, errors> canonicalize_pathname(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-an-opaque-pathname
tl::expected<std::string, errors> canonicalize_opaque_pathname(
    std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-search
tl::expected<std::string, errors> canonicalize_search(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-hash
tl::expected<std::string, errors> canonicalize_hash(std::string_view input);

// @see https://urlpattern.spec.whatwg.org/#tokenize
tl::expected<std::vector<token>, errors> tokenize(std::string_view input,
                                                  token_policy policy);

// @see https://urlpattern.spec.whatwg.org/#process-a-base-url-string
std::string process_base_url_string(std::string_view input,
                                    url_pattern_init::process_type type);

// @see https://urlpattern.spec.whatwg.org/#escape-a-pattern-string
std::string escape_pattern_string(std::string_view input);

// @see https://urlpattern.spec.whatwg.org/#escape-a-regexp-string
std::string escape_regexp_string(std::string_view input);

// @see https://urlpattern.spec.whatwg.org/#is-an-absolute-pathname
constexpr bool is_absolute_pathname(
    std::string_view input, url_pattern_init::process_type type) noexcept;

// @see https://urlpattern.spec.whatwg.org/#parse-a-pattern-string
template <url_pattern_encoding_callback F>
tl::expected<std::vector<url_pattern_part>, errors> parse_pattern_string(
    std::string_view input, url_pattern_compile_component_options& options,
    F& encoding_callback);

// @see https://urlpattern.spec.whatwg.org/#generate-a-pattern-string
std::string generate_pattern_string(
    std::vector<url_pattern_part>& part_list,
    url_pattern_compile_component_options& options);

// @see
// https://urlpattern.spec.whatwg.org/#generate-a-regular-expression-and-name-list
std::tuple<std::string, std::vector<std::string>>
generate_regular_expression_and_name_list(
    const std::vector<url_pattern_part>& part_list,
    url_pattern_compile_component_options options);

// @see https://urlpattern.spec.whatwg.org/#hostname-pattern-is-an-ipv6-address
bool is_ipv6_address(std::string_view input) noexcept;

// @see
// https://urlpattern.spec.whatwg.org/#protocol-component-matches-a-special-scheme
template <url_pattern_regex::regex_concept regex_provider>
bool protocol_component_matches_special_scheme(
    ada::url_pattern_component<regex_provider>& input);

// @see https://urlpattern.spec.whatwg.org/#convert-a-modifier-to-a-string
std::string convert_modifier_to_string(url_pattern_part_modifier modifier);

// @see https://urlpattern.spec.whatwg.org/#generate-a-segment-wildcard-regexp
std::string generate_segment_wildcard_regexp(
    url_pattern_compile_component_options options);

}  // namespace ada::url_pattern_helpers

#endif
