/**
 * @file url_pattern.h
 * @brief Declaration for the URLPattern implementation.
 */
#ifndef ADA_URL_PATTERN_H
#define ADA_URL_PATTERN_H

#include "ada/implementation.h"
#include "ada/expected.h"

#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#if ADA_TESTING
#include <iostream>
#endif  // ADA_TESTING

namespace ada {
namespace parser {
template <typename result_type, typename url_pattern_init,
          typename url_pattern_options, typename regex_provider>
tl::expected<result_type, errors> parse_url_pattern_impl(
    std::variant<std::string_view, url_pattern_init> input,
    const std::string_view* base_url, const url_pattern_options* options);
} // namespace parser

enum class url_pattern_part_type : uint8_t {
  // The part represents a simple fixed text string.
  FIXED_TEXT,
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
class url_pattern_part {
 public:
  url_pattern_part(url_pattern_part_type _type, std::string&& _value,
                   url_pattern_part_modifier _modifier)
      : type(_type), value(_value), modifier(_modifier) {}

  url_pattern_part(url_pattern_part_type _type, std::string&& _value,
                   url_pattern_part_modifier _modifier, std::string&& _name,
                   std::string&& _prefix, std::string&& _suffix)
      : type(_type),
        value(_value),
        modifier(_modifier),
        name(_name),
        prefix(_prefix),
        suffix(_suffix) {}
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
      std::optional<char> new_delimiter = std::nullopt,
      std::optional<char> new_prefix = std::nullopt)
      : delimiter(new_delimiter), prefix(new_prefix) {}

  std::string_view get_delimiter() const ada_warn_unused;
  std::string_view get_prefix() const ada_warn_unused;

  // @see https://urlpattern.spec.whatwg.org/#options-ignore-case
  bool ignore_case = false;

  static url_pattern_compile_component_options DEFAULT;
  static url_pattern_compile_component_options HOSTNAME;
  static url_pattern_compile_component_options PATHNAME;

 private:
  // @see https://urlpattern.spec.whatwg.org/#options-delimiter-code-point
  std::optional<char> delimiter{};
  // @see https://urlpattern.spec.whatwg.org/#options-prefix-code-point
  std::optional<char> prefix{};
};

// A struct providing the URLPattern matching results for a single
// URL component. The URLPatternComponentResult is only ever used
// as a member attribute of a URLPatternResult struct. The
// URLPatternComponentResult API is defined as part of the URLPattern
// specification.
struct url_pattern_component_result {
  std::string input;
  std::unordered_map<std::string, std::string> groups;

  bool operator==(const url_pattern_component_result&) const;

#if ADA_TESTING
  friend void PrintTo(const url_pattern_component_result& result,
                      std::ostream* os) {
    *os << "input: '" << result.input << "', group: ";
    for (const auto& group : result.groups) {
      *os << "(" << group.first << ", " << group.second << ") ";
    }
  }
#endif  // ADA_TESTING
};

template <url_pattern_regex::regex_concept regex_provider>
class url_pattern_component {
 public:
  url_pattern_component() = default;

  // This function explicitly takes a std::string because it is moved.
  // To avoid unnecessary copy, move each value while calling the constructor.
  url_pattern_component(std::string&& new_pattern,
                        typename regex_provider::regex_type&& new_regexp,
                        std::vector<std::string>&& new_group_name_list,
                        bool new_has_regexp_groups)
      : regexp(std::move(new_regexp)),
        pattern(std::move(new_pattern)),
        group_name_list(new_group_name_list),
        has_regexp_groups(new_has_regexp_groups) {}

  // @see https://urlpattern.spec.whatwg.org/#compile-a-component
  template <url_pattern_encoding_callback F>
  static tl::expected<url_pattern_component, errors> compile(
      std::string_view input, F& encoding_callback,
      url_pattern_compile_component_options& options);

  // @see https://urlpattern.spec.whatwg.org/#create-a-component-match-result
  url_pattern_component_result create_component_match_result(
      std::string_view input, std::vector<std::string>&& exec_result);

  std::string to_string() const;

  typename regex_provider::regex_type regexp{};
  std::string pattern{};
  std::vector<std::string> group_name_list{};
  bool has_regexp_groups = false;
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

  std::string to_string() const;
};

// URLPattern is a Web Platform standard API for matching URLs against a
// pattern syntax (think of it as a regular expression for URLs). It is
// defined in https://wicg.github.io/urlpattern.
// More information about the URL Pattern syntax can be found at
// https://developer.mozilla.org/en-US/docs/Web/API/URL_Pattern_API
template <url_pattern_regex::regex_concept regex_provider>
class url_pattern {
 public:
  url_pattern() = default;

  /**
   * @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-exec
   */
  result<std::optional<url_pattern_result>> exec(const url_pattern_input& input,
                                                 std::string_view* base_url);

  /**
   * @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-test
   */
  result<bool> test(const url_pattern_input& input, std::string_view* base_url);

  /**
   * @see https://urlpattern.spec.whatwg.org/#url-pattern-match
   * This function expects a valid UTF-8 string if input is a string.
   */
  result<std::optional<url_pattern_result>> match(
      const url_pattern_input& input, std::string_view* base_url_string);

  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-protocol
  [[nodiscard]] std::string_view get_protocol() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-username
  [[nodiscard]] std::string_view get_username() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-password
  [[nodiscard]] std::string_view get_password() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-hostname
  [[nodiscard]] std::string_view get_hostname() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-port
  [[nodiscard]] std::string_view get_port() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-pathname
  [[nodiscard]] std::string_view get_pathname() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-search
  [[nodiscard]] std::string_view get_search() const ada_lifetime_bound;
  // @see https://urlpattern.spec.whatwg.org/#dom-urlpattern-hash
  [[nodiscard]] std::string_view get_hash() const ada_lifetime_bound;

  // If ignoreCase is true, the JavaScript regular expression created for each
  // pattern must use the `vi` flag. Otherwise, they must use the `v` flag.
  [[nodiscard]] bool ignore_case() const;

  // @see https://urlpattern.spec.whatwg.org/#url-pattern-has-regexp-groups
  [[nodiscard]] bool has_regexp_groups() const;

  [[nodiscard]] std::string to_string() const;

  url_pattern_component<regex_provider> protocol_component{};
  url_pattern_component<regex_provider> username_component{};
  url_pattern_component<regex_provider> password_component{};
  url_pattern_component<regex_provider> hostname_component{};
  url_pattern_component<regex_provider> port_component{};
  url_pattern_component<regex_provider> pathname_component{};
  url_pattern_component<regex_provider> search_component{};
  url_pattern_component<regex_provider> hash_component{};
  bool ignore_case_ = false;

  template <typename result_type, typename url_pattern_init,
            typename url_pattern_options, typename regex_provider>
  friend tl::expected<result_type, errors> parser::parse_url_pattern_impl(
      std::variant<std::string_view, url_pattern_init> input,
      const std::string_view* base_url, const url_pattern_options* options);
};



}  // namespace ada

#endif
