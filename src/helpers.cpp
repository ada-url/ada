#include <vector>
#include <algorithm>
#include <cstring>

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

  ada_really_inline uint64_t string_to_uint64(std::string_view view) {
    uint64_t val;
    std::memcpy(&val, view.data(), sizeof(uint64_t));
    return val;
  }

  std::string from_decimal(std::string& res, uint16_t base, uint16_t input) {
      while (input > 0) {
        int num = input % base;
        if (num >= 0 && num <= 9) {
          res += static_cast<char>(num + '0');
        } else {
          res += static_cast<char>(num - 10 + 'a');
        }
        input /= base;
      }

      std::reverse(res.begin(), res.end());

      return res;
  }

} // namespace ada::helpers
