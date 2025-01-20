#include <regex>
#include "ada/url_pattern_regex.h"

namespace ada::url_pattern_regex {
std::optional<std::regex> std_regex_provider::create_instance(
    std::string_view pattern, bool ignore_case) {
  // Let flags be an empty string.
  // If options’s ignore case is true then set flags to "vi".
  // Otherwise set flags to "v"
  auto flags = ignore_case
                   ? std::regex::icase | std::regex_constants::ECMAScript
                   : std::regex_constants::ECMAScript;
  try {
    return std::regex(pattern.data(), pattern.size(), flags);
  } catch (const std::regex_error& e) {
    (void)e;
    ada_log("std_regex_provider::create_instance failed:", e.what());
    return std::nullopt;
  }
}

std::vector<std::string> std_regex_provider::regex_search(
    std::string_view input, const std::regex& pattern) {

    std::vector<std::string> matches;
    std::string input_str(input.begin(), input.end());  // Convert string_view to string for regex_search
    std::smatch match_result;

    while (std::regex_search(input_str, match_result, pattern)) {
        matches.push_back(match_result.str());
        input_str = match_result.suffix().str();
    }
    return matches;
}

bool std_regex_provider::regex_match(std::string_view input,
                                     const std::regex& pattern) {
  return std::regex_match(input.data(), input.begin(), pattern);
}

}  // namespace ada::url_pattern_regex
