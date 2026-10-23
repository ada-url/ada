#include <string_view>

namespace ada {

// Empty segments (a leading or repeated '&') are not pairs.
size_t urlencoded_pair_count(std::string_view input) noexcept {
  size_t pairs = 0;
  for (size_t i = 0; i < input.size();) {
    if (input[i] == '&') {
      ++i;
      continue;
    }
    ++pairs;
    const size_t amp = input.find('&', i);
    if (amp == std::string_view::npos) {
      break;
    }
    i = amp + 1;
  }
  return pairs;
}

}  // namespace ada
