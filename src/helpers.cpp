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

  std::string get_state(ada::state state) {
    switch (state) {
      case AUTHORITY: return "Authority";
      case SCHEME_START: return "Scheme Start";
      case SCHEME: return "Scheme";
      case HOST: return "Host";
      case NO_SCHEME: return "No Scheme";
      case FRAGMENT: return "Fragment";
      case RELATIVE: return "Relative";
      case RELATIVE_SLASH: return "Relative Slash";
      case FILE: return "File";
      case FILE_HOST: return "File Host";
      case FILE_SLASH: return "File Slash";
      case PATH_OR_AUTHORITY: return "Path or Authority";
      case SPECIAL_AUTHORITY_IGNORE_SLASHES: return "Special Authority Ignore Slashes";
      case SPECIAL_AUTHORITY_SLASHES: return "Special Authority Slashes";
      case SPECIAL_RELATIVE_OR_AUTHORITY: return "Special Relative or Authority";
      case QUERY: return "Query";
      case PATH: return "Path";
      case PATH_START: return "Path Start";
      case OPAQUE_PATH: return "Opaque Path";
      case PORT: return "Port";
      default: return "";
    }
  }

} // namespace ada::helpers
