/**
 * @file url_pattern_init.h
 * @brief Declaration for the url_pattern_init implementation.
 */
#ifndef ADA_URL_PATTERN_INIT_H
#define ADA_URL_PATTERN_INIT_H

#include "ada/expected.h"
#include "ada/errors.h"

#include <string_view>
#include <string>
#include <optional>

#if ADA_TESTING
#include <iostream>
#endif  // ADA_TESTING

namespace ada {

// Important: C++20 allows us to use concept rather than `using` or `typedef
// and allows functions with second argument, which is optional (using either
// std::nullopt or a parameter with default value)
template <typename F>
concept url_pattern_encoding_callback = requires(F f, std::string_view sv) {
  { f(sv) } -> std::same_as<tl::expected<std::string, errors>>;
};

// A structure providing matching patterns for individual components
// of a URL. When a URLPattern is created, or when a URLPattern is
// used to match or test against a URL, the input can be given as
// either a string or a URLPatternInit struct. If a string is given,
// it will be parsed to create a URLPatternInit. The URLPatternInit
// API is defined as part of the URLPattern specification.
// All provided strings must be valid UTF-8.
struct url_pattern_init {
  enum class process_type : uint8_t {
    url,
    pattern,
  };

  // All strings must be valid UTF-8.
  // @see https://urlpattern.spec.whatwg.org/#process-a-urlpatterninit
  static tl::expected<url_pattern_init, errors> process(
      const url_pattern_init& init, process_type type,
      std::optional<std::string_view> protocol = std::nullopt,
      std::optional<std::string_view> username = std::nullopt,
      std::optional<std::string_view> password = std::nullopt,
      std::optional<std::string_view> hostname = std::nullopt,
      std::optional<std::string_view> port = std::nullopt,
      std::optional<std::string_view> pathname = std::nullopt,
      std::optional<std::string_view> search = std::nullopt,
      std::optional<std::string_view> hash = std::nullopt);

  // @see https://urlpattern.spec.whatwg.org/#process-protocol-for-init
  static tl::expected<std::string, errors> process_protocol(
      std::string_view value, process_type type);

  // @see https://urlpattern.spec.whatwg.org/#process-username-for-init
  static tl::expected<std::string, errors> process_username(
      std::string_view value, process_type type);

  // @see https://urlpattern.spec.whatwg.org/#process-password-for-init
  static tl::expected<std::string, errors> process_password(
      std::string_view value, process_type type);

  // @see https://urlpattern.spec.whatwg.org/#process-hostname-for-init
  static tl::expected<std::string, errors> process_hostname(
      std::string_view value, process_type type);

  // @see https://urlpattern.spec.whatwg.org/#process-port-for-init
  static tl::expected<std::string, errors> process_port(
      std::string_view port, std::string_view protocol, process_type type);

  // @see https://urlpattern.spec.whatwg.org/#process-pathname-for-init
  static tl::expected<std::string, errors> process_pathname(
      std::string_view value, std::string_view protocol, process_type type);

  // @see https://urlpattern.spec.whatwg.org/#process-search-for-init
  static tl::expected<std::string, errors> process_search(
      std::string_view value, process_type type);

  // @see https://urlpattern.spec.whatwg.org/#process-hash-for-init
  static tl::expected<std::string, errors> process_hash(std::string_view value,
                                                        process_type type);

#if ADA_TESTING
  friend void PrintTo(const url_pattern_init& init, std::ostream* os) {
    *os << "protocol: '" << init.protocol.value_or("undefined") << "', ";
    *os << "username: '" << init.username.value_or("undefined") << "', ";
    *os << "password: '" << init.password.value_or("undefined") << "', ";
    *os << "hostname: '" << init.hostname.value_or("undefined") << "', ";
    *os << "port: '" << init.port.value_or("undefined") << "', ";
    *os << "pathname: '" << init.pathname.value_or("undefined") << "', ";
    *os << "search: '" << init.search.value_or("undefined") << "', ";
    *os << "hash: '" << init.hash.value_or("undefined") << "', ";
    *os << "base_url: '" << init.base_url.value_or("undefined") << "', ";
  }
#endif  // ADA_TESTING

  bool operator==(const url_pattern_init&) const;
  // If present, must be valid UTF-8.
  std::optional<std::string> protocol{};
  // If present, must be valid UTF-8.
  std::optional<std::string> username{};
  // If present, must be valid UTF-8.
  std::optional<std::string> password{};
  // If present, must be valid UTF-8.
  std::optional<std::string> hostname{};
  // If present, must be valid UTF-8.
  std::optional<std::string> port{};
  // If present, must be valid UTF-8.
  std::optional<std::string> pathname{};
  // If present, must be valid UTF-8.
  std::optional<std::string> search{};
  // If present, must be valid UTF-8.
  std::optional<std::string> hash{};
  // If present, must be valid UTF-8.
  std::optional<std::string> base_url{};
};
}  // namespace ada

#endif  // ADA_URL_PATTERN_INIT_H
