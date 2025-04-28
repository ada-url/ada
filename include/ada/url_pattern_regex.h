/**
 * @file url_search_params.h
 * @brief Declaration for the URL Search Params
 */
#ifndef ADA_URL_PATTERN_REGEX_H
#define ADA_URL_PATTERN_REGEX_H

#include <string>
#include <string_view>

#ifdef ADA_USE_UNSAFE_STD_REGEX_PROVIDER
#include <regex>
#endif  // ADA_USE_UNSAFE_STD_REGEX_PROVIDER

#if ADA_INCLUDE_URL_PATTERN
namespace ada::url_pattern_regex {

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
