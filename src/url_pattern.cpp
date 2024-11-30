#include "ada.h"

#include <optional>
#include <string>

namespace ada {

URLPattern::Component::Component(std::string_view pattern,
                                 std::string_view regex,
                                 const std::vector<std::string>& names) {
  // TODO: Implement this
  return {.pattern = pattern, .regex = regex, .names = std::move(names)};
}

std::optional<URLPattern::Result> URLPattern::exec(
    std::optional<Input> input, std::optional<std::string> base_url) {
  // TODO: Implement this
  return std::nullopt;
}

bool URLPattern::test(std::optional<Input> input,
                      std::optional<std::string_view> base_url) {
  // TODO: Implement this
  return false;
}

}  // namespace ada
