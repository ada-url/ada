#include <vector>
#include <algorithm>
#include <cstring>
#include <sstream>

namespace ada::helpers {

  std::vector<std::string_view> split_string_view(std::string_view input, char delimiter, bool skip_empty) {
    std::vector<std::string_view> out;
    if (input.empty()) { return out; }
    size_t pos{0};
    size_t end_pos{0};
    while((end_pos = input.find(delimiter, pos)) != std::string_view::npos) {
      // we have a match!
      auto start = input.data() + pos;
      size_t size = end_pos - pos;
      pos = end_pos + 1; // next time, we start from there...
      if(skip_empty && (size == 0)) { continue; }
      out.emplace_back(std::string_view{start, size});
    }
    if(pos < input.size()) {
      size_t size = input.size() - pos;
      out.emplace_back(std::string_view{input.data() + pos, size});
    }
    return out;
  }

  ada_unused std::string get_state(ada::state state) {
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

} // namespace ada::helpers
