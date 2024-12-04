/**
 * @file url_pattern.h
 * @brief Declaration for the URLPattern implementation.
 */
#ifndef ADA_URL_PATTERN_H
#define ADA_URL_PATTERN_H

#include <string>
#include <unordered_map>
#include <variant>

namespace ada {

namespace url_pattern {

enum class errors { type_error };

// @see https://urlpattern.spec.whatwg.org/#canonicalize-a-protocol
std::optional<std::string> canonicalize_protocol(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-username
std::optional<std::string> canonicalize_username(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-password
std::optional<std::string> canonicalize_password(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-password
std::optional<std::string> canonicalize_hostname(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-an-ipv6-hostname
std::optional<std::string> canonicalize_ipv6_hostname(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-port
std::optional<std::string> canonicalize_port(
    std::string_view input, std::string_view protocol = "fake");

// @see https://wicg.github.io/urlpattern/#canonicalize-a-pathname
std::optional<std::string> canonicalize_pathname(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-an-opaque-pathname
std::optional<std::string> canonicalize_opaque_pathname(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-search
std::optional<std::string> canonicalize_search(std::string_view input);

// @see https://wicg.github.io/urlpattern/#canonicalize-a-hash
std::optional<std::string> canonicalize_hash(std::string_view input);

}  // namespace url_pattern

// URLPattern is a Web Platform standard API for matching URLs against a
// pattern syntax (think of it as a regular expression for URLs). It is
// defined in https://wicg.github.io/urlpattern.
// More information about the URL Pattern syntax can be found at
// https://developer.mozilla.org/en-US/docs/Web/API/URL_Pattern_API
class URLPattern {
 public:
  class Component {
   public:
    explicit Component(std::string_view pattern, std::string_view regex,
                       const std::vector<std::string>& names);

    std::string_view get_pattern() const noexcept ada_lifetime_bound;
    std::string_view get_regex() const noexcept ada_lifetime_bound;
    const std::vector<std::string>& get_names() const noexcept
        ada_lifetime_bound;

   private:
    // Disallow copy.
    Component(const Component&);

    // The normalized pattern for this component.
    std::string pattern = "";
    // The generated JavaScript regular expression for this component.
    std::string regex = "";
    // The list of sub-component names extracted for this component.
    std::vector<std::string> names{};
  };

  // A structure providing matching patterns for individual components
  // of a URL. When a URLPattern is created, or when a URLPattern is
  // used to match or test against a URL, the input can be given as
  // either a string or a URLPatternInit struct. If a string is given,
  // it will be parsed to create a URLPatternInit. The URLPatternInit
  // API is defined as part of the URLPattern specification.
  struct Init {
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

  using Input = std::variant<std::string, Init>;

  // A struct providing the URLPattern matching results for a single
  // URL component. The URLPatternComponentResult is only ever used
  // as a member attribute of a URLPatternResult struct. The
  // URLPatternComponentResult API is defined as part of the URLPattern
  // specification.
  struct ComponentResult {
    std::string input;
    std::unordered_map<std::string, std::string> groups;
  };

  // A struct providing the URLPattern matching results for all
  // components of a URL. The URLPatternResult API is defined as
  // part of the URLPattern specification.
  struct Result {
    std::vector<Input> inputs;
    ComponentResult protocol;
    ComponentResult username;
    ComponentResult password;
    ComponentResult hostname;
    ComponentResult port;
    ComponentResult pathname;
    ComponentResult search;
    ComponentResult hash;
  };

  struct Options {
    bool ignore_case = false;
  };

  explicit URLPattern(std::optional<Input> input,
                      std::optional<std::string_view> base_url,
                      std::optional<Options> options);

  std::optional<Result> exec(std::optional<Input> input,
                             std::optional<std::string> base_url);
  bool test(std::optional<Input> input,
            std::optional<std::string_view> base_url);

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
  bool case_ignored() const ada_lifetime_bound;

 private:
  Component protocol;
  Component username;
  Component password;
  Component hostname;
  Component port;
  Component pathname;
  Component search;
  Component hash;
  bool ignore_case = false;
};

}  // namespace ada

#endif
