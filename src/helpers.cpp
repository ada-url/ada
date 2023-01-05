#include <vector>
#include <algorithm>
#include <cstring>
#include <sstream>

namespace ada::helpers {

  std::vector<std::string> split_string_view(std::string_view input, char delimiter, bool skip_empty) {
    std::vector<std::string> out;
    if (input.empty())
      return out;
    std::istringstream in_stream(std::string{input});
    while (in_stream.good()) {
      std::string item;
      std::getline(in_stream, item, delimiter);
      if (item.empty() && skip_empty) continue;
      out.emplace_back(std::move(item));
    }
    return out;
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
