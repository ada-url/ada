#include <vector>

namespace ada::helpers {

  std::vector<std::string_view> split_string_view(std::string_view input, std::string_view delimiter) {
    std::vector<std::string_view> output{};
    size_t pointer = 0;

    while (pointer < input.size()) {
      const auto next = input.find_first_of(delimiter, pointer);

      if (pointer != next)
        output.emplace_back(input.substr(pointer, next - pointer));

      if (next == std::string_view::npos)
        break;

      pointer = next + 1;
    }

    return output;
  }

  std::string join_vector_string(std::vector<std::string_view> input, std::string_view delimiter) {
    std::string output{};
    auto pointer = input.begin();

    while (pointer <= input.end()) {
      output += *pointer;
      if (pointer != input.end()) {
        output += delimiter;
      }
    }

    return output;
  }

} // namespace ada::helpers
