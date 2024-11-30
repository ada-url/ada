/**
 * @file url_pattern.h
 * @brief Declaration for the URLPattern implementation.
 */
#ifndef ADA_URL_PATTERN_H
#define ADA_URL_PATTERN_H

#include <string>
#include <unordered_map>

namespace ada {

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

    // TODO(anonrig): Move these implementations to `url_pattern-inl.h`
    std::string_view get_pattern() const noexcept ada_lifetime_bound {
      return pattern;
    }
    std::string_view get_regex() const noexcept ada_lifetime_bound {
      return regex;
    }
    const std::vector<std::string>& get_names() const noexcept
        ada_lifetime_bound {
      return names;
    }

   private:
    // Disallow copy.
    Component(const Component&);

    // The normalized pattern for this component.
    std::string pattern = "";
    // The generated JavaScript regular expression for this component.
    std::string regex = "";
    // The list of sub-component names extracted for this component.
    std::vector<std::string> names;
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

  // TODO(anonrig): Move these to `url_pattern-inl.h`.
  const Component& get_protocol() const ada_lifetime_bound { return protocol; }
  const Component& get_username() const ada_lifetime_bound { return username; }
  const Component& get_password() const ada_lifetime_bound { return password; }
  const Component& get_port() const ada_lifetime_bound { return port; }
  const Component& get_pathname() const ada_lifetime_bound { return pathname; }
  const Component& get_search() const ada_lifetime_bound { return search; }
  const Component& get_hash() const ada_lifetime_bound { return hash; }

  // If ignoreCase is true, the JavaScript regular expression created for each
  // pattern must use the `vi` flag. Otherwise, they must use the `v` flag.
  // TODO(anonrig): Move these to `url_pattern-inl.h`.
  bool case_ignored() const ada_lifetime_bound { return ignore_case; }

 private:
  Component protocol;
  Component username;
  Component password;
  Component port;
  Component pathname;
  Component search;
  Component hash;
  bool ignore_case = false;
};

}  // namespace ada

#endif