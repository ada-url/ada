#include <algorithm>
#include <charconv>
#include <cstring>
#include <sstream>

namespace ada::helpers {

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

  // prune_fragment seeks the first '#' and returns everything after it as a
  // strint_view, and modifies (in place) the input so that it points at everything
  // before the '#'.
  // If no '#' is found, the input is left unchanged and std::nullopt is returned.
  // Note that the returned string_view might be empty!
  // The function is non-allocating and it does not throw.
  ada_really_inline std::optional<std::string_view> prune_fragment(std::string_view& input) noexcept {
    // compiles down to 20--30 instructions including a class to memchr (C function).
    // this function should be quite fast.
    size_t location_of_first = input.find('#');
    if(location_of_first == std::string_view::npos) { return std::nullopt; }
    std::string_view fragment = input;
    fragment.remove_prefix(location_of_first+1);
    input.remove_suffix(input.size() - location_of_first);
    return fragment;
  }

  std::optional<uint16_t> get_port_fast(std::string_view::iterator begin, std::string_view::iterator end) noexcept {
    uint16_t port{};
    std::string_view view(begin, end-begin);
    auto r = std::from_chars(view.data(), view.data() + view.size() , port);
    if (r.ec != std::errc()) { return std::nullopt; }
    return port;
}

} // namespace ada::helpers
