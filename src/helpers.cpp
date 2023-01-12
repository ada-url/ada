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
  // string_view, and modifies (in place) the input so that it points at everything
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

  std::optional<uint16_t> get_port(const std::string_view::iterator begin, const std::string_view::iterator end) noexcept {
    uint16_t port{};
    std::string_view view(begin, end-begin);
    auto r = std::from_chars(view.data(), view.data() + view.size() , port);
    if (r.ec != std::errc()) { return std::nullopt; }
    return port;
  }

  /**
   * @return True if the state machine execution should finish.
   */
  bool parse_port(std::string_view::iterator &pointer_start,
                  std::string_view::iterator pointer_end,
                  ada::state &state,
                  bool &is_valid,
                  std::optional<uint16_t> &out,
                  const bool is_url_special,
                  const bool state_override_given) noexcept {
    std::string_view::iterator first_non_digit = std::find_if_not(pointer_start, pointer_end, ::ada::checkers::is_digit);
    std::string_view buffer = std::string_view(pointer_start, first_non_digit - pointer_start);
    pointer_start += buffer.length();

    // Otherwise, if one of the following is true:
    // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
    // - url is special and c is U+005C (\)
    // - state override is given
    if (pointer_start == pointer_end || *first_non_digit == '/' || *first_non_digit == '?' ||
        (is_url_special && *first_non_digit == '\\') ||
        state_override_given) {

      // If buffer is not the empty string, then:
      if (!buffer.empty()) {
        // Let port be the mathematical integer value that is represented by buffer in radix-10
        // using ASCII digits for digits with values 0 through 9.
        std::optional<uint16_t> port = helpers::get_port(buffer.begin(), buffer.end());

        // If port is greater than 216 − 1, validation error, return failure.
        // Set url’s port to null, if port is url’s scheme’s default port; otherwise to port.
        if (!port.has_value()) {
          is_valid = false;
          return true;
        }

        out = port;
      }

      // If state override is given, then return.
      if (state_override_given) {
        return true;
      }

      // Set state to path start state and decrease pointer by 1.
      state = PATH_START;
      pointer_start--;
    }
    // Otherwise, validation error, return failure.
    else {
      is_valid = false;
      return true;
    }

    return false;
  }

} // namespace ada::helpers
