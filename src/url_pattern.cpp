#include "ada.h"

#include <optional>
#include <string>

namespace ada {

URLPattern::Component::Component(std::string_view pattern_,
                                 std::string_view regex_,
                                 const std::vector<std::string>& names_) {
  // TODO: Implement this
  pattern = pattern_;
  regex = regex_;
  names = std::move(names_);
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
