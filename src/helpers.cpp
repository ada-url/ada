#include "ada.h"
#include "ada/common_defs.h" // make sure ADA_IS_BIG_ENDIAN gets defined.
#include "ada/unicode.h"
#include "ada/scheme.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <sstream>

namespace ada::helpers {

  template <typename out_iter>
  void encode_json(std::string_view view, out_iter out) {
    // trivial implementation. could be faster.
    const char * hexvalues = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    for(uint8_t c : view) {
      if(c == '\\') {
        *out++ = '\\'; *out++ = '\\';
      } else if(c == '"') {
        *out++ = '\\'; *out++ = '"';
      } else if(c <= 0x1f) {
        *out++ = '\\'; *out++= 'u'; *out++= '0'; *out++= '0';
        *out++ = hexvalues[2*c];
        *out++ = hexvalues[2*c+1];
      } else {
        *out++ = c;
      }
    }
  }

  ada_unused std::string get_state(ada::state s) {
    switch (s) {
      case ada::state::AUTHORITY: return "Authority";
      case ada::state::SCHEME_START: return "Scheme Start";
      case ada::state::SCHEME: return "Scheme";
      case ada::state::HOST: return "Host";
      case ada::state::NO_SCHEME: return "No Scheme";
      case ada::state::FRAGMENT: return "Fragment";
      case ada::state::RELATIVE_SCHEME: return "Relative Scheme";
      case ada::state::RELATIVE_SLASH: return "Relative Slash";
      case ada::state::FILE: return "File";
      case ada::state::FILE_HOST: return "File Host";
      case ada::state::FILE_SLASH: return "File Slash";
      case ada::state::PATH_OR_AUTHORITY: return "Path or Authority";
      case ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES: return "Special Authority Ignore Slashes";
      case ada::state::SPECIAL_AUTHORITY_SLASHES: return "Special Authority Slashes";
      case ada::state::SPECIAL_RELATIVE_OR_AUTHORITY: return "Special Relative or Authority";
      case ada::state::QUERY: return "Query";
      case ada::state::PATH: return "Path";
      case ada::state::PATH_START: return "Path Start";
      case ada::state::OPAQUE_PATH: return "Opaque Path";
      case ada::state::PORT: return "Port";
      default: return "unknown state";
    }
  }

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

  ada_really_inline void shorten_path(std::string& path, ada::scheme::type type) noexcept {
    size_t first_delimiter = path.find_first_of('/', 1);

    // Let path be url’s path.
    // If url’s scheme is "file", path’s size is 1, and path[0] is a normalized Windows drive letter, then return.
    if (type == ada::scheme::type::FILE && first_delimiter == std::string_view::npos) {
      if (checkers::is_normalized_windows_drive_letter(std::string_view(path.data() + 1, first_delimiter - 1))) {
        return;
      }
    }

    // Remove path’s last item, if any.
    if (!path.empty()) {
      path.erase(path.rfind('/'));
    }
  }

  ada_really_inline void remove_ascii_tab_or_newline(std::string& input) noexcept {
    // if this ever becomes a performance issue, we could use an approach similar to has_tabs_or_newline
    input.erase(std::remove_if(input.begin(), input.end(), [](char c) {
      return ada::unicode::is_ascii_tab_or_newline(c);
    }), input.end());
  }

  ada_really_inline std::string_view substring(std::string_view input, size_t pos) noexcept {
    ada_log("substring(", input, " [", input.size() ,"bytes],", pos, ")");
    return pos > input.size() ? std::string_view() : input.substr(pos);
  }

  // Reverse the byte order.
  ada_really_inline uint64_t swap_bytes(uint64_t val) {
        return ((((val) & 0xff00000000000000ull) >> 56) |
                (((val) & 0x00ff000000000000ull) >> 40) |
                (((val) & 0x0000ff0000000000ull) >> 24) |
                (((val) & 0x000000ff00000000ull) >> 8 ) |
                (((val) & 0x00000000ff000000ull) << 8 ) |
                (((val) & 0x0000000000ff0000ull) << 24) |
                (((val) & 0x000000000000ff00ull) << 40) |
                (((val) & 0x00000000000000ffull) << 56));
  }

  // starting at index location, this finds the next location of a character
  // :, /, \\, ? or [. If none is found, view.size() is returned.
  // For use within get_host_delimiter_location.
  ada_really_inline size_t find_next_host_delimiter_special(std::string_view view, size_t location) noexcept {
    auto has_zero_byte = [](uint64_t v) {
      return ((v - 0x0101010101010101) & ~(v)&0x8080808080808080);
    };
    auto index_of_first_set_byte = [](uint64_t v) {
#if ADA_IS_BIG_ENDIAN
      v = swap_bytes(v);
#endif
      return ((((v - 1) & 0x101010101010101) * 0x101010101010101) >> 56) - 1;
    };
    auto broadcast = [](uint8_t v) -> uint64_t { return 0x101010101010101 * v; };
    size_t i = location;
    uint64_t mask1 = broadcast(':');
    uint64_t mask2 = broadcast('/');
    uint64_t mask3 = broadcast('\\');
    uint64_t mask4 = broadcast('?');
    uint64_t mask5 = broadcast('[');
    for (; i + 7 < view.size(); i += 8) {
      uint64_t word{};
      memcpy(&word, view.data() + i, sizeof(word));
      uint64_t xor1 = word ^ mask1;
      uint64_t xor2 = word ^ mask2;
      uint64_t xor3 = word ^ mask3;
      uint64_t xor4 = word ^ mask4;
      uint64_t xor5 = word ^ mask5;
      uint64_t is_match = has_zero_byte(xor1) | has_zero_byte(xor2) | has_zero_byte(xor3) | has_zero_byte(xor4) | has_zero_byte(xor5);
      if(is_match) {
        return i + index_of_first_set_byte(is_match);
      }
    }
    if (i < view.size()) {
      uint64_t word{};
      memcpy(&word, view.data() + i, view.size() - i);
      uint64_t xor1 = word ^ mask1;
      uint64_t xor2 = word ^ mask2;
      uint64_t xor3 = word ^ mask3;
      uint64_t xor4 = word ^ mask4;
      uint64_t xor5 = word ^ mask5;
      uint64_t is_match = has_zero_byte(xor1) | has_zero_byte(xor2) | has_zero_byte(xor3) | has_zero_byte(xor4) | has_zero_byte(xor5);
      if(is_match) {
        return i + index_of_first_set_byte(is_match);
      }
    }
    return view.size();
  }

  // starting at index location, this finds the next location of a character
  // :, /, ? or [. If none is found, view.size() is returned.
  // For use within get_host_delimiter_location.
  ada_really_inline size_t find_next_host_delimiter(std::string_view view, size_t location) noexcept {
    auto has_zero_byte = [](uint64_t v) {
      return ((v - 0x0101010101010101) & ~(v)&0x8080808080808080);
    };
    auto index_of_first_set_byte = [](uint64_t v) {
#if ADA_IS_BIG_ENDIAN
      v = swap_bytes(v);
#endif
      return ((((v - 1) & 0x101010101010101) * 0x101010101010101) >> 56) - 1;

    };
    auto broadcast = [](uint8_t v) -> uint64_t { return 0x101010101010101 * v; };
    size_t i = location;
    uint64_t mask1 = broadcast(':');
    uint64_t mask2 = broadcast('/');
    uint64_t mask4 = broadcast('?');
    uint64_t mask5 = broadcast('[');
    for (; i + 7 < view.size(); i += 8) {
      uint64_t word{};
      memcpy(&word, view.data() + i, sizeof(word));
      uint64_t xor1 = word ^ mask1;
      uint64_t xor2 = word ^ mask2;
      uint64_t xor4 = word ^ mask4;
      uint64_t xor5 = word ^ mask5;
      uint64_t is_match = has_zero_byte(xor1) | has_zero_byte(xor2) | has_zero_byte(xor4) | has_zero_byte(xor5);
      if(is_match) {
        return i + index_of_first_set_byte(is_match);
      }
    }
    if (i < view.size()) {
      uint64_t word{};
      memcpy(&word, view.data() + i, view.size() - i);
      uint64_t xor1 = word ^ mask1;
      uint64_t xor2 = word ^ mask2;
      uint64_t xor4 = word ^ mask4;
      uint64_t xor5 = word ^ mask5;
      uint64_t is_match = has_zero_byte(xor1) | has_zero_byte(xor2) | has_zero_byte(xor4) | has_zero_byte(xor5);
      if(is_match) {
        return i + index_of_first_set_byte(is_match);
      }
    }
    return view.size();
  }

  ada_really_inline std::pair<size_t,bool> get_host_delimiter_location(const bool is_special, std::string_view& view) noexcept {
    /**
     * The spec at https://url.spec.whatwg.org/#hostname-state expects us to compute
     * a variable called insideBrackets but this variable is only used once, to check
     * whether a ':' character was found outside brackets.
     * Exact text:
     * "Otherwise, if c is U+003A (:) and insideBrackets is false, then:".
     * It is conceptually simpler and arguably more efficient to just return a Boolean
     * indicating whether ':' was found outside brackets.
     */
    const size_t view_size = view.size();
    size_t location = 0;
    bool found_colon = false;
    /**
     * Performance analysis:
     *
     * Here, we are basically seeking the end of the hostname which can be indicated
     * by the end of the view, or by one of the characters ':', '/', '?', '\\' (where '\\' is only
     * applicable for special URLs). However, these must appear outside a bracket range. E.g.,
     * if you have [something?]fd: then the '?' does not count.
     *
     * So we can skip ahead to the next delimiter, as long as we include '[' in the set of delimiters,
     * and that we handle it first.
     *
     * So the trick is to have a fast function that locates the next delimiter. Unless we find '[',
     * then it only needs to be called once! Ideally, such a function would be provided by the C++
     * standard library, but it seems that find_first_of is not very fast, so we are forced to roll
     * our own.
     *
     * We do not break into two loops for speed, but for clarity.
     */
    if(is_special) {
      // We move to the next delimiter.
      location = find_next_host_delimiter_special(view, location);
      // Unless we find '[' then we are going only going to have to call
      // find_next_host_delimiter_special once.
      for (;location < view_size; location = find_next_host_delimiter_special(view, location)) {
        if (view[location] == '[') {
          location = view.find(']', location);
          if (location == std::string_view::npos) {
            break;
          }
        } else {
          found_colon = view[location] == ':';
          break;
        }
      }
    } else {
      // We move to the next delimiter.
      location = find_next_host_delimiter(view, location);
      // Unless we find '[' then we are going only going to have to call
      // find_next_host_delimiter_special once.
      for (;location < view_size; location = find_next_host_delimiter(view, location)) {
        if (view[location] == '[') {
          location = view.find(']', location);
          if (location == std::string_view::npos) {
            break;
          }
        } else {
          found_colon = view[location] == ':';
          break;
        }
      }
    }

    if (location != std::string_view::npos) {
      view.remove_suffix(view_size - location);
    }

    return {location, found_colon};
  }

  ada_really_inline void trim_c0_whitespace(std::string_view& input) noexcept {
    while(!input.empty() && ada::unicode::is_c0_control_or_space(input.front())) { input.remove_prefix(1); }
    while(!input.empty() && ada::unicode::is_c0_control_or_space(input.back())) { input.remove_suffix(1); }
  }


  ada_really_inline bool parse_prepared_path(std::string_view input, ada::scheme::type type, std::string& path) {
    ada_log("parse_path ", input);
    uint8_t accumulator = checkers::path_signature(input);
    // Let us first detect a trivial case.
    // If it is special, we check that we have no dot, no %,  no \ and no
    // character needing percent encoding. Otherwise, we check that we have no %,
    // no dot, and no character needing percent encoding.
    bool special = type != ada::scheme::NOT_SPECIAL;
    bool trivial_path =
        (special ? (accumulator == 0) : ((accumulator & 0b11111101) == 0)) &&
        (type != ada::scheme::type::FILE);
    if (trivial_path) {
      ada_log("parse_path trivial");
      path += '/';
      path += input;
      return true;
    }
    // We are going to need to look a bit at the path, but let us see if we can
    // ignore percent encoding *and* backslashes *and* percent characters.
    // Except for the trivial case, this is likely to capture 99% of paths out
    // there.
    bool fast_path = (special && (accumulator & 0b11111011) == 0) &&
                    (type != ada::scheme::type::FILE);
    if (fast_path) {
      ada_log("parse_path fast");
      // Here we don't need to worry about \ or percent encoding.
      // We also do not have a file protocol. We might have dots, however,
      // but dots must as appear as '.', and they cannot be encoded because
      // the symbol '%' is not present.
      size_t previous_location = 0; // We start at 0.
      do {
        size_t new_location = input.find('/', previous_location);
        //std::string_view path_view = input;
        // We process the last segment separately:
        if (new_location == std::string_view::npos) {
          std::string_view path_view = input.substr(previous_location);
          if (path_view == "..") { // The path ends with ..
            // e.g., if you receive ".." with an empty path, you go to "/".
            if(path.empty()) { path = '/'; return true; }
            // Fast case where we have nothing to do:
            if(path.back() == '/') { return true; }
            // If you have the path "/joe/myfriend",
            // then you delete 'myfriend'.
            path.resize(path.rfind('/') + 1);
            return true;
          }
          path += '/';
          if (path_view != ".") {
            path.append(path_view);
          }
          return true;
        } else {
          // This is a non-final segment.
          std::string_view path_view = input.substr(previous_location, new_location - previous_location);
          previous_location = new_location + 1;
          if (path_view == "..") {
            if(!path.empty()) { path.erase(path.rfind('/')); }
          } else if (path_view != ".") {
            path += '/';
            path.append(path_view);
          }
        }
      } while (true);
    } else {
      ada_log("parse_path slow");
      // we have reached the general case
      bool needs_percent_encoding = (accumulator & 1);
      std::string path_buffer_tmp;
      do {
        size_t location = (special && (accumulator & 2))
                              ? input.find_first_of("/\\")
                              : input.find('/');
        std::string_view path_view = input;
        if (location != std::string_view::npos) {
          path_view.remove_suffix(path_view.size() - location);
          input.remove_prefix(location + 1);
        }
        // path_buffer is either path_view or it might point at a percent encoded temporary file.
        std::string_view path_buffer =
         (needs_percent_encoding
           && ada::unicode::percent_encode(path_view, character_sets::PATH_PERCENT_ENCODE, path_buffer_tmp)) ?
          path_buffer_tmp :
          path_view;
        if (unicode::is_double_dot_path_segment(path_buffer)) {
          helpers::shorten_path(path, type);
          if (location == std::string_view::npos) {
            path += '/';
          }
        } else if (unicode::is_single_dot_path_segment(path_buffer) &&
                  (location == std::string_view::npos)) {
          path += '/';
        }
        // Otherwise, if path_buffer is not a single-dot path segment, then:
        else if (!unicode::is_single_dot_path_segment(path_buffer)) {
          // If url’s scheme is "file", url’s path is empty, and path_buffer is a
          // Windows drive letter, then replace the second code point in
          // path_buffer with U+003A (:).
          if (type == ada::scheme::type::FILE && path.empty() &&
              checkers::is_windows_drive_letter(path_buffer)) {
            path += '/';
            path += path_buffer[0];
            path += ':';
            path_buffer.remove_prefix(2);
            path.append(path_buffer);
          } else {
            // Append path_buffer to url’s path.
            path += '/';
            path.append(path_buffer);
          }
        }
        if (location == std::string_view::npos) {
          return true;
        }
      } while (true);
    }
  }

  ada_really_inline void strip_trailing_spaces_from_opaque_path(ada::url& url) noexcept {
    if (!url.has_opaque_path) return;
    if (url.fragment.has_value()) return;
    if (url.query.has_value()) return;
    while (!url.path.empty() && url.path.back() == ' ') { url.path.resize(url.path.size()-1); }
  }
} // namespace ada::helpers

namespace ada {
  ada_warn_unused std::string to_string(ada::state state) {
    return ada::helpers::get_state(state);
  }
}
