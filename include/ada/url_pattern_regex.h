/**
 * @file url_search_params.h
 * @brief Declaration for the URL Search Params
 */
#ifndef ADA_URL_PATTERN_REGEX_H
#define ADA_URL_PATTERN_REGEX_H

#include <concepts>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef ADA_USE_UNSAFE_STD_REGEX_PROVIDER
#include <regex>
#endif  // ADA_USE_UNSAFE_STD_REGEX_PROVIDER

#if ADA_INCLUDE_URL_PATTERN
namespace ada::url_pattern_regex {

/**
 * @brief Concept defining the interface for regex engine providers used by
 * URLPattern.
 *
 * A regex provider supplies the regular expression engine used for
 * pattern compilation and matching.
 *
 * Requirements:
 * - typename T::regex_type: The compiled regex object type.
 * - T::create_instance(pattern, ignore_case): Compiles the regex pattern
 * string. Returns std::nullopt if the pattern is invalid or cannot be compiled.
 * - T::regex_search(input, pattern): Executes a regex search against the input,
 *     returning a vector of capture group values (with std::nullopt for
 * unmatched optional groups) or std::nullopt if the input does not match.
 * - T::regex_match(input, pattern): Returns true if the input matches the
 * pattern, or false otherwise.
 *
 * Exception contract:
 * Provider methods may throw exceptions (for example, on allocation failure,
 * input length limits, complexity limits, or internal engine errors). In
 * environments where C++ exceptions are enabled, exceptions thrown by the
 * provider will propagate out of URLPattern functions (such as fast_test,
 * fast_match, test, exec, match, etc.). Providers that prefer non-throwing
 * operation should handle internal errors and return false or std::nullopt.
 */
template <typename T>
concept regex_concept = requires(T t, std::string_view pattern,
                                 bool ignore_case, std::string_view input) {
  // Ensure the class has a type alias 'regex_type'
  typename T::regex_type;

  // Function to create a regex instance
  {
    T::create_instance(pattern, ignore_case)
  } -> std::same_as<std::optional<typename T::regex_type>>;

  // Function to perform regex search
  {
    T::regex_search(input, std::declval<typename T::regex_type&>())
  } -> std::same_as<std::optional<std::vector<std::optional<std::string>>>>;

  // Function to match regex pattern
  {
    T::regex_match(input, std::declval<typename T::regex_type&>())
  } -> std::same_as<bool>;

  // Copy constructor
  { T(std::declval<const T&>()) } -> std::same_as<T>;

  // Move constructor
  { T(std::declval<T&&>()) } -> std::same_as<T>;
};

#ifdef ADA_USE_UNSAFE_STD_REGEX_PROVIDER
class std_regex_provider final {
 public:
  std_regex_provider() = default;
  using regex_type = std::regex;
  static std::optional<regex_type> create_instance(std::string_view pattern,
                                                   bool ignore_case);
  static std::optional<std::vector<std::optional<std::string>>> regex_search(
      std::string_view input, const regex_type& pattern);
  static bool regex_match(std::string_view input, const regex_type& pattern);
};
#endif  // ADA_USE_UNSAFE_STD_REGEX_PROVIDER

}  // namespace ada::url_pattern_regex
#endif  // ADA_INCLUDE_URL_PATTERN
#endif  // ADA_URL_PATTERN_REGEX_H
