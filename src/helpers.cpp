#include "ada.h"
#include "ada/unicode.h"

#include <algorithm>
#include <cstring>

namespace ada::helpers {

  ada_unused std::string get_state(ada::state state) {
    switch (state) {
      case ada::state::AUTHORITY:
        return "Authority";
      case ada::state::SCHEME_START:
        return "Scheme Start";
      case ada::state::SCHEME:
        return "Scheme";
      case ada::state::HOST:
        return "Host";
      case ada::state::NO_SCHEME:
        return "No Scheme";
      case ada::state::FRAGMENT:
        return "Fragment";
      case ada::state::RELATIVE:
        return "Relative";
      case ada::state::RELATIVE_SLASH:
        return "Relative Slash";
      case ada::state::FILE:
        return "File";
      case ada::state::FILE_HOST:
        return "File Host";
      case ada::state::FILE_SLASH:
        return "File Slash";
      case ada::state::PATH_OR_AUTHORITY:
        return "Path or Authority";
      case ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES:
        return "Special Authority Ignore Slashes";
      case ada::state::SPECIAL_AUTHORITY_SLASHES:
        return "Special Authority Slashes";
      case ada::state::SPECIAL_RELATIVE_OR_AUTHORITY:
        return "Special Relative or Authority";
      case ada::state::QUERY:
        return "Query";
      case ada::state::PATH:
        return "Path";
      case ada::state::PATH_START:
        return "Path Start";
      case ada::state::OPAQUE_PATH:
        return "Opaque Path";
      case ada::state::PORT:
        return "Port";
      default:
        unreachable();
    }
  }

  // prune_fragment seeks the first '#' and returns everything after it as a
  // string_view, and modifies (in place) the input so that it points at everything
  // before the '#'.
  // If no '#' is found, the input is left unchanged and std::nullopt is returned.
  // Note that the returned string_view might be empty!
  // The function is non-allocating and it does not throw.
  ada_really_inline std::optional<std::string_view> prune_fragment(std::string_view &input) noexcept {
    // compiles down to 20--30 instructions including a class to memchr (C function).
    // this function should be quite fast.
    size_t location_of_first = input.find('#');
    if (location_of_first == std::string_view::npos) { return std::nullopt; }
    std::string_view fragment = input;
    fragment.remove_prefix(location_of_first + 1);
    input.remove_suffix(input.size() - location_of_first);
    return fragment;
  }

  /**
   * @see https://url.spec.whatwg.org/#shorten-a-urls-path
   *
   * This function assumes url does not have an opaque path.
   */
  ada_really_inline void shorten_path(ada::url &url) noexcept {
    size_t first_delimiter = url.path.find_first_of('/', 1);

    // Let path be url’s path.
    // If url’s scheme is "file", path’s size is 1, and path[0] is a normalized Windows drive letter, then return.
    if (url.get_scheme_type() == ada::scheme::type::FILE && first_delimiter == std::string_view::npos) {
      if (checkers::is_normalized_windows_drive_letter(std::string_view(url.path.data() + 1, first_delimiter - 1))) {
        return;
      }
    }

    // Remove path’s last item, if any.
    if (!url.path.empty()) {
      url.path.erase(url.path.rfind('/'));
    }
  }

  ada_really_inline void remove_ascii_tab_or_newline(std::string &input) noexcept {
    // if this ever becomes a performance issue, we could use an approach similar to has_tabs_or_newline
    input.erase(std::remove_if(input.begin(), input.end(), [](char c) {
      return ada::unicode::is_ascii_tab_or_newline(c);
    }), input.end());
  }

  ada_really_inline size_t
  get_host_delimiter_location(const ada::url &url, std::string_view &view, bool &inside_brackets) noexcept {
    size_t location = url.is_special() ? view.find_first_of(":[/?\\") : view.find_first_of(":[/?");

    // Next while loop is almost never taken!
    while ((location != std::string_view::npos) && (view[location] == '[')) {
      location = view.find(']', location);
      if (location == std::string_view::npos) {
        inside_brackets = true;
        /**
         * TODO: Ok. So if we arrive here then view has an unclosed [,
         * Is the URL valid???
         */
      } else {
        location = url.is_special() ? view.find_first_of(":[/?\\#", location) : view.find_first_of(":[/?#", location);
      }
    }

    if (location != std::string_view::npos) {
      view.remove_suffix(view.size() - location);
    }
    return location;
  }

} // namespace ada::helpers

namespace ada {
  ada_warn_unused std::string to_string(ada::state state) {
    return ada::helpers::get_state(state);
  }
}
