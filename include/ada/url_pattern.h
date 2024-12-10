/**
 * @file url_pattern.h
 * @brief Declaration for the URLPattern implementation.
 */
#ifndef ADA_URL_PATTERN_H
#define ADA_URL_PATTERN_H

#include "ada/expected.h"

#include <string>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <vector>

namespace ada {

enum class url_pattern_errors : uint8_t { type_error };

namespace parser {
template <typename result_type, typename url_pattern_init,
          typename url_pattern_options>
tl::expected<result_type, url_pattern_errors> parse_url_pattern(
    std::variant<std::string_view, url_pattern_init> input,
    const std::string_view* base_url, const url_pattern_options* options);
}

// Important: C++20 allows us to use concept rather than `using` or `typedef
// and allows functions with second argument, which is optional (using either
// std::nullopt or a parameter with default value)
template <typename F>
concept url_pattern_encoding_callback = requires(F f, std::string_view sv) {
  { f(sv) } -> std::same_as<tl::expected<std::string, url_pattern_errors>>;
} || requires(F f, std::string_view sv, std::string_view opt) {
  { f(sv, opt) } -> std::same_as<tl::expected<std::string, url_pattern_errors>>;
};

// A structure providing matching patterns for individual components
// of a URL. When a URLPattern is created, or when a URLPattern is
// used to match or test against a URL, the input can be given as
// either a string or a URLPatternInit struct. If a string is given,
// it will be parsed to create a URLPatternInit. The URLPatternInit
// API is defined as part of the URLPattern specification.
struct url_pattern_init {
  // @see https://urlpattern.spec.whatwg.org/#process-a-urlpatterninit
  static tl::expected<url_pattern_init, url_pattern_errors> process(
      url_pattern_init init, std::string type,
      std::optional<std::string_view> protocol = std::nullopt,
      std::optional<std::string_view> username = std::nullopt,
      std::optional<std::string_view> password = std::nullopt,
      std::optional<std::string_view> hostname = std::nullopt,
      std::optional<std::string_view> port = std::nullopt,
      std::optional<std::string_view> pathname = std::nullopt,
      std::optional<std::string_view> search = std::nullopt,
      std::optional<std::string_view> hash = std::nullopt);

  // @see https://urlpattern.spec.whatwg.org/#process-protocol-for-init
  static tl::expected<std::string, url_pattern_errors> process_protocol(
      std::string_view value, std::string_view type);

  // @see https://urlpattern.spec.whatwg.org/#process-username-for-init
  static tl::expected<std::string, url_pattern_errors> process_username(
      std::string_view value, std::string_view type);

  // @see https://urlpattern.spec.whatwg.org/#process-password-for-init
  static tl::expected<std::string, url_pattern_errors> process_password(
      std::string_view value, std::string_view type);

  // @see https://urlpattern.spec.whatwg.org/#process-hostname-for-init
  static tl::expected<std::string, url_pattern_errors> process_hostname(
      std::string_view value, std::string_view type);

  // @see https://urlpattern.spec.whatwg.org/#process-port-for-init
  static tl::expected<std::string, url_pattern_errors> process_port(
      std::string_view port, std::string_view protocol, std::string_view type);

  // @see https://urlpattern.spec.whatwg.org/#process-pathname-for-init
  static tl::expected<std::string, url_pattern_errors> process_pathname(
      std::string_view value, std::string_view protocol, std::string_view type);

  // @see https://urlpattern.spec.whatwg.org/#process-search-for-init
  static tl::expected<std::string, url_pattern_errors> process_search(
      std::string_view value, std::string_view type);

  // @see https://urlpattern.spec.whatwg.org/#process-hash-for-init
  static tl::expected<std::string, url_pattern_errors> process_hash(
      std::string_view value, std::string_view type);

  std::optional<std::string> protocol;
  std::optional<std::string> username;
  std::optional<std::string> password;
  std::optional<std::string> hostname;
  std::optional<std::string> port;
  std::optional<std::string> pathname;
  std::optional<std::string> search;
  std::optional<std::string> hash;

  std::optional<std::string> base_url;
};

enum class url_pattern_part_type : uint8_t {
  // The part represents a simple fixed text string.
  FIXED_TEST,
  // The part represents a matching group with a custom regular expression.
  REGEXP,
  // The part represents a matching group that matches code points up to the
  // next separator code point. This is typically used for a named group like
  // ":foo" that does not have a custom regular expression.
  SEGMENT_WILDCARD,
  // The part represents a matching group that greedily matches all code points.
  // This is typically used for the "*" wildcard matching group.
  FULL_WILDCARD,
};

enum class url_pattern_part_modifier : uint8_t {
  // The part does not have a modifier.
  NONE,
  // The part has an optional modifier indicated by the U+003F (?) code point.
  OPTIONAL,
  // The part has a "zero or more" modifier indicated by the U+002A (*) code
  // point.
  ZERO_OR_MORE,
  // The part has a "one or more" modifier indicated by the U+002B (+) code
  // point.
  ONE_OR_MORE,
};

// @see https://urlpattern.spec.whatwg.org/#part
struct url_pattern_part {
  // A part has an associated type, a string, which must be set upon creation.
  url_pattern_part_type type;
  // A part has an associated value, a string, which must be set upon creation.
  std::string value;
  // A part has an associated modifier a string, which must be set upon
  // creation.
  url_pattern_part_modifier modifier;
  // A part has an associated name, a string, initially the empty string.
  std::string name{};
  // A part has an associated prefix, a string, initially the empty string.
  std::string prefix{};
  // A part has an associated suffix, a string, initially the empty string.
  std::string suffix{};

  inline bool is_regexp() const noexcept;
};

// @see https://urlpattern.spec.whatwg.org/#options-header
struct url_pattern_compile_component_options {
  url_pattern_compile_component_options() = default;
  explicit url_pattern_compile_component_options(
      std::optional<char> delimiter = std::nullopt,
      std::optional<char> prefix = std::nullopt)
      : delimiter(delimiter), prefix(prefix){};

  // @see https://urlpattern.spec.whatwg.org/#options-delimiter-code-point
  std::optional<char> delimiter{};
  // @see https://urlpattern.spec.whatwg.org/#options-prefix-code-point
  std::optional<char> prefix{};
  // @see https://urlpattern.spec.whatwg.org/#options-ignore-case
  bool ignore_case = false;

  static url_pattern_compile_component_options DEFAULT;
  static url_pattern_compile_component_options HOSTNAME;
  static url_pattern_compile_component_options PATHNAME;
};

class url_pattern_component {
 public:
  url_pattern_component() = default;

  // This function explicitly takes a std::string because it is moved.
  // To avoid unnecessary copy, move each value while calling the constructor.
  url_pattern_component(std::string pattern, std::string regexp,
                        std::vector<std::string> group_name_list,
                        bool has_regexp_groups)
      : pattern(std::move(pattern)),
        regexp(std::move(regexp)),
        group_name_list(std::move(group_name_list)),
        has_regexp_groups_(has_regexp_groups){};

  // @see https://urlpattern.spec.whatwg.org/#compile-a-component
  template <url_pattern_encoding_callback F>
  static url_pattern_component compile(
      std::string_view input, F encoding_callback,
      url_pattern_compile_component_options& options);

  std::string_view get_pattern() const noexcept ada_lifetime_bound;
  std::string_view get_regexp() const noexcept ada_lifetime_bound;
  const std::vector<std::string>& get_group_name_list() const noexcept
      ada_lifetime_bound;
  bool has_regexp_groups() const noexcept ada_lifetime_bound;

 private:
  // The normalized pattern for this component.
  std::string pattern = "";
  // The generated JavaScript regular expression for this component.
  std::string regexp = "";
  // The list of sub-component names extracted for this component.
  std::vector<std::string> group_name_list{};

  bool has_regexp_groups_ = false;
};

// A struct providing the URLPattern matching results for a single
// URL component. The URLPatternComponentResult is only ever used
// as a member attribute of a URLPatternResult struct. The
// URLPatternComponentResult API is defined as part of the URLPattern
// specification.
struct url_pattern_component_result {
  std::string input;
  std::unordered_map<std::string, std::string> groups;
};

using url_pattern_input = std::variant<std::string_view, url_pattern_init>;

// A struct providing the URLPattern matching results for all
// components of a URL. The URLPatternResult API is defined as
// part of the URLPattern specification.
struct url_pattern_result {
  std::vector<url_pattern_input> inputs;
  url_pattern_component_result protocol;
  url_pattern_component_result username;
  url_pattern_component_result password;
  url_pattern_component_result hostname;
  url_pattern_component_result port;
  url_pattern_component_result pathname;
  url_pattern_component_result search;
  url_pattern_component_result hash;
};

struct url_pattern_options {
  bool ignore_case = false;
};

// URLPattern is a Web Platform standard API for matching URLs against a
// pattern syntax (think of it as a regular expression for URLs). It is
// defined in https://wicg.github.io/urlpattern.
// More information about the URL Pattern syntax can be found at
// https://developer.mozilla.org/en-US/docs/Web/API/URL_Pattern_API
class url_pattern {
 public:
  url_pattern() = default;
  explicit url_pattern(std::optional<url_pattern_input> input,
                       std::optional<std::string_view> base_url,
                       std::optional<url_pattern_options> options);

  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-exec
  tl::expected<url_pattern_result, url_pattern_errors> exec(
      std::variant<url_pattern_init, url_aggregator> input,
      std::string_view* base_url);
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-test
  bool test(std::variant<url_pattern_init, url_aggregator> input,
            std::string_view* base_url);

  // @see https://urlpattern.spec.whatwg.org/#url-pattern-match
  tl::expected<url_pattern_result, url_pattern_errors> match(
      std::variant<url_pattern_init, url_aggregator> input,
      std::string_view* base_url_string);

  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-protocol
  std::string_view get_protocol() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-username
  std::string_view get_username() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-password
  std::string_view get_password() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-hostname
  std::string_view get_hostname() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-port
  std::string_view get_port() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-pathname
  std::string_view get_pathname() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-search
  std::string_view get_search() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-hash
  std::string_view get_hash() const ada_lifetime_bound;

  // If ignoreCase is true, the JavaScript regular expression created for each
  // pattern must use the `vi` flag. Otherwise, they must use the `v` flag.
  bool ignore_case() const ada_lifetime_bound;

  // @see https://urlpattern.spec.whatwg.org/#url-pattern-has-regexp-groups
  bool has_regexp_groups() const ada_lifetime_bound;

 private:
  url_pattern_component protocol_component{};
  url_pattern_component username_component{};
  url_pattern_component password_component{};
  url_pattern_component hostname_component{};
  url_pattern_component port_component{};
  url_pattern_component pathname_component{};
  url_pattern_component search_component{};
  url_pattern_component hash_component{};
  bool ignore_case_ = false;

  template <typename result_type, typename url_pattern_init,
            typename url_pattern_options>
  friend tl::expected<result_type, url_pattern_errors>
  parser::parse_url_pattern(
      std::variant<std::string_view, url_pattern_init> input,
      const std::string_view* base_url, const url_pattern_options* options);
};

namespace url_pattern_helpers {

// @see https://urlpattern.spec.whatwg.org/#tokens
struct Token {
  // @see https://urlpattern.spec.whatwg.org/#tokenize-policy
  enum class Policy {
    STRICT,
    LENIENT,
  };

  // @see https://urlpattern.spec.whatwg.org/#token
  enum class Type {
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
};

// @see https://urlpattern.spec.whatwg.org/#tokenizer
struct Tokenizer {
  explicit Tokenizer(std::string_view input, Token::Policy policy)
      : input(input), policy(policy) {}

  // has an associated input, a pattern string, initially the empty string.
  std::string input{};
  // has an associated policy, a tokenize policy, initially "strict".
  Token::Policy policy = Token::Policy::STRICT;
  // has an associated token list, a token list, initially an empty list.
  std::vector<Token> token_list{};
  // has an associated index, a number, initially 0.
  size_t index = 0;
  // has an associated next index, a number, initially 0.
  size_t next_index = 0;
  // has an associated code point, a Unicode code point, initially null.
  char* code_point = nullptr;
};

// @see https://urlpattern.spec.whatwg.org/#constructor-string-parser
struct constructor_string_parser {
  explicit constructor_string_parser(std::string_view input,
                                     std::vector<Token>& token_list);

 private:
  // @see https://urlpattern.spec.whatwg.org/#constructor-string-parser-state
  enum class State {
    INIT,
    PROTOCOL,
    AUTHORITY,
    PASSWORD,
    HOSTNAME,
    PORT,
    PATHNAME,
    SEARCH,
    HASH,
    DONE,
  };
  // has an associated input, a string, which must be set upon creation.
  std::string input;
  // has an associated token list, a token list, which must be set upon
  // creation.
  std::vector<Token> token_list;
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
tl::expected<std::string, url_pattern_errors> canonicalize_protocol(
    std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-username
tl::expected<std::string, url_pattern_errors> canonicalize_username(
    std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-password
tl::expected<std::string, url_pattern_errors> canonicalize_password(
    std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-password
tl::expected<std::string, url_pattern_errors> canonicalize_hostname(
    std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-an-ipv6-hostname
tl::expected<std::string, url_pattern_errors> canonicalize_ipv6_hostname(
    std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-port
tl::expected<std::string, url_pattern_errors> canonicalize_port(
    std::string_view input, std::string_view protocol = "fake");

// @see https://wicg.github.io/urlpattern/#canonicalize-a-pathname
tl::expected<std::string, url_pattern_errors> canonicalize_pathname(
    std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-an-opaque-pathname
tl::expected<std::string, url_pattern_errors> canonicalize_opaque_pathname(
    std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-search
tl::expected<std::string, url_pattern_errors> canonicalize_search(
    std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-hash
tl::expected<std::string, url_pattern_errors> canonicalize_hash(
    std::string_view input);

// @see https://urlpattern.spec.whatwg.org/#parse-a-constructor-string
url_pattern_init parse_constructor_string(std::string_view input);

// @see https://urlpattern.spec.whatwg.org/#tokenize
std::string tokenize(std::string_view input, Token::Policy policy);

// @see https://urlpattern.spec.whatwg.org/#process-a-base-url-string
std::string process_base_url_string(std::string_view input,
                                    std::string_view type);

// @see https://urlpattern.spec.whatwg.org/#escape-a-pattern-string
std::string escape_pattern(std::string_view input);

// @see https://urlpattern.spec.whatwg.org/#escape-a-regexp-string
std::string escape_regexp_string(std::string_view input);

// @see https://urlpattern.spec.whatwg.org/#is-an-absolute-pathname
constexpr bool is_absolute_pathname(std::string_view input,
                                    std::string_view type) noexcept;

// @see https://urlpattern.spec.whatwg.org/#parse-a-pattern-string
template <url_pattern_encoding_callback F>
std::vector<url_pattern_part> parse_pattern_string(
    std::string_view pattern,
    const url_pattern_compile_component_options& options, F encoding_callback);

// @see https://urlpattern.spec.whatwg.org/#generate-a-pattern-string
std::string generate_pattern_string(
    std::vector<url_pattern_part>& part_list,
    url_pattern_compile_component_options& options);

// @see
// https://urlpattern.spec.whatwg.org/#generate-a-regular-expression-and-name-list
std::tuple<std::string, std::vector<std::string>>
generate_regular_expression_and_name_list(
    std::vector<url_pattern_part>& part_list,
    url_pattern_compile_component_options options);

// @see https://urlpattern.spec.whatwg.org/#hostname-pattern-is-an-ipv6-address
constexpr bool is_ipv6_address(std::string_view input) noexcept;

// @see
// https://urlpattern.spec.whatwg.org/#protocol-component-matches-a-special-scheme
bool protocol_component_matches_special_scheme(std::string_view input);

// @see https://urlpattern.spec.whatwg.org/#convert-a-modifier-to-a-string
std::string convert_modifier_to_string(url_pattern_part_modifier modifier);

// @see https://urlpattern.spec.whatwg.org/#generate-a-segment-wildcard-regexp
std::string generate_segment_wildcard_regexp(
    url_pattern_compile_component_options options);

}  // namespace url_pattern_helpers

}  // namespace ada

#endif
