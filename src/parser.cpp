#include "ada.h"
#include "unicode.cpp"
#include "parser.h"
#include "scheme.cpp"

#include <cctype>

namespace ada {

  url_parser::url_parser(std::string_view user_input, std::optional<ada::url> optional_base_url, std::optional<ada::encoding_type> encoding_override,
                 std::optional<ada::state> given_state_override) {
    // Assign base_url if it exists
    base_url = optional_base_url;

    // TODO: If input contains any ASCII tab or newline, validation error.
    // TODO: Remove all ASCII tab or newline from input.

    // Let state be state override if given, or scheme start state otherwise.
    state_override = given_state_override;

    // Set encoding to the result of getting an output encoding from encoding.
    if (encoding_override.has_value()) {
      encoding = encoding_override.value();
    }

    // Define parsed URL
    url = ada::url();

    // Store original input
    input = user_input;

    // Remove any leading and trailing C0 control or space from input.
    pointer_start = std::find_if(user_input.begin(), user_input.end(), [](unsigned char c) {
      return !ada::unicode::is_c0_control_or_space(c);
    });
    pointer_end = std::find_if(user_input.rbegin(), user_input.rend(), [](unsigned char c) {
      return !ada::unicode::is_c0_control_or_space(c);
    }).base();

    // Define parsed URL
    url = ada::url();
    // If input contains any leading or trailing C0 control or space, validation error.
    url.has_validation_error = pointer_start != user_input.begin() || pointer_end != user_input.end() - 1;

    // Let pointer be a pointer for input.
    pointer = pointer_start;

    // Keep running the following state machine by switching on state.
    // If after a run pointer points to the EOF code point, go to the next step.
    // Otherwise, increase pointer by 1 and continue with the state machine.
    for (; pointer <= pointer_end && url.is_valid; pointer++) {
      parse_state();
    }
  }

  void url_parser::parse_state() {
    switch (state) {
      case SCHEME_START: {
        // If c is an ASCII alpha, append c, lowercased, to buffer, and set state to scheme state.
        if (ada::unicode::is_ascii_alpha(*pointer)) {
          buffer += static_cast<char>(tolower(*pointer));
          state = SCHEME;
        }
        // Otherwise, if state override is not given, set state to no scheme state and decrease pointer by 1.
        else if (!state_override.has_value()) {
          state = NO_SCHEME;
          pointer--;
        }
        // Otherwise, validation error, return failure.
        else {
          url.has_validation_error = true;
          url.is_valid = false;
        }
      }
      case SCHEME: {
        // If c is an ASCII alphanumeric, U+002B (+), U+002D (-), or U+002E (.), append c, lowercased, to buffer.
        if (ada::unicode::is_ascii_alphanumeric(*pointer) || *pointer == '+' || *pointer == '-' || *pointer == '.') {
          buffer += static_cast<char>(tolower(*pointer));
        }
        // Otherwise, if c is U+003A (:), then:
        else if (*pointer == ':') {
          // If state override is given, then:
          if (state_override.has_value()) {
            // If url’s scheme is a special scheme and buffer is not a special scheme, then return.
            // If url’s scheme is not a special scheme and buffer is a special scheme, then return.
            if (ada::scheme::is_special(url.scheme) != ada::scheme::is_special(buffer)) {
              return;
            }

            // If url includes credentials or has a non-null port, and buffer is "file", then return.
            if ((url.includes_credentials() || url.port.has_value()) && buffer == "file") {
              return;
            }

            // If url’s scheme is "file" and its host is an empty host, then return.
            if (url.scheme == "file" && (!url.host.has_value() || url.host->empty())) {
              return;
            }
          }

          // Set url’s scheme to buffer.
          url.scheme = buffer;

          // If state override is given, then:
          if (state_override.has_value()) {
            auto urls_scheme_port = ada::scheme::SPECIAL_SCHEME.find(url.scheme);

            // If url’s port is url’s scheme’s default port, then set url’s port to null.
            if (url.port.value() == urls_scheme_port->second) {
              url.port = NULL;
            }

            return;
          }

          // Set buffer to the empty string.
          buffer = "";

          // If url’s scheme is "file", then:
          if (url.scheme == "file") {
            // If remaining does not start with "//", validation error.
            if (std::distance(pointer, pointer_end) < 2 && pointer[1] == '/' && pointer[2] == '/') {
              url.has_validation_error = true;
            }
            // Set state to file state.
            state = FILE;
          }
          // Otherwise, if url is special, base is non-null, and base’s scheme is url’s scheme:
          else if (url.is_special() && base_url.has_value() && base_url->scheme == url.scheme) {
            // Set state to special relative or authority state.
            state = SPECIAL_RELATIVE_OR_AUTHORITY;
          }
          // Otherwise, if url is special, set state to special authority slashes state.
          else if (url.is_special()) {
            state = SPECIAL_AUTHORITY_SLASHES;
          }
          // Otherwise, if remaining starts with an U+002F (/), set state to path or authority state
          // and increase pointer by 1.
          else if (std::distance(pointer, pointer_end) < 1 && pointer[1] == '/') {
            state = PATH_OR_AUTHORITY;
            pointer++;
          }
          // Otherwise, set url’s path to the empty string and set state to opaque path state.
          else {
            url.path = "";
            state = OPAQUE_PATH;
          }
        }
        // Otherwise, if state override is not given, set buffer to the empty string, state to no scheme state,
        // and start over (from the first code point in input).
        else if (!state_override.has_value()) {
          buffer = "";
          state = NO_SCHEME;
          pointer = pointer_start;
          pointer--;
        }
        // Otherwise, validation error, return failure.
        else {
          url.has_validation_error = true;
          url.is_valid = false;
        }
      }
      case SPECIAL_RELATIVE_OR_AUTHORITY: {
        // If c is U+002F (/) and remaining starts with U+002F (/),
        // then set state to special authority ignore slashes state and increase pointer by 1.
        if (*pointer == '/' && std::distance(pointer, pointer_end) < 1 && pointer[1] == '/') {
          state = SPECIAL_AUTHORITY_IGNORE_SLASHES;
          pointer++;
        }
        // Otherwise, validation error, set state to relative state and decrease pointer by 1.
        else {
          url.has_validation_error = true;
          state = RELATIVE;
          pointer--;
        }
      }
      case PATH_OR_AUTHORITY: {
        // If c is U+002F (/), then set state to authority state.
        if (*pointer == '/') {
          state = AUTHORITY;
        }
        // Otherwise, set state to path state, and decrease pointer by 1.
        else {
          state = PATH;
          pointer--;
        }
      }
      case RELATIVE_SLASH: {
        // If url is special and c is U+002F (/) or U+005C (\), then:
        if (url.is_special() && (*pointer == '/' || *pointer =='\\')) {
          // If c is U+005C (\), validation error.
          if (*pointer == '\\') {
            url.has_validation_error = true;
          }

          // Set state to special authority ignore slashes state.
          state = SPECIAL_AUTHORITY_IGNORE_SLASHES;
        }
        // Otherwise, if c is U+002F (/), then set state to authority state.
        else if (*pointer == '/') {
          state = AUTHORITY;
        }
        // Otherwise, set
        // - url’s username to base’s username,
        // - url’s password to base’s password,
        // - url’s host to base’s host,
        // - url’s port to base’s port,
        // - state to path state, and then, decrease pointer by 1.
        else {
          if (base_url.has_value()) {
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
          }
          state = PATH;
          pointer--;
        }
      }
      default:
        printf("not implemented");
    }
  }

  ada::url url_parser::get_url() {
    return url;
  }

} // namespace ada
