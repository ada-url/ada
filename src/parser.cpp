#include "ada.h"
#include "unicode.cpp"
#include "parser.h"
#include "scheme.cpp"

#include <cassert>
#include <cctype>

namespace ada {

  Parser::Parser(std::string_view user_input, std::optional<ada::URL> optional_base_url, std::optional<ada::encoding_type> encoding_override,
                 std::optional<ada::state> given_state_override) {
    // Assign base_url if it exists
    base_url = optional_base_url;

    // TODO: If input contains any leading or trailing C0 control or space, validation error.
    // TODO: Remove any leading and trailing C0 control or space from input.

    // TODO: If input contains any ASCII tab or newline, validation error.
    // TODO: Remove all ASCII tab or newline from input.

    // Let state be state override if given, or scheme start state otherwise.
    state_override = given_state_override;

    // Set encoding to the result of getting an output encoding from encoding.
    if (encoding_override.has_value()) {
      encoding = encoding_override.value();
    }

    // Store original input
    input = user_input;

    // Let pointer be a pointer for input.
    pointer = input.begin();

    // Define parsed URL
    url = ada::URL();

    // Keep running the following state machine by switching on state.
    // If after a run pointer points to the EOF code point, go to the next step.
    // Otherwise, increase pointer by 1 and continue with the state machine.
    for (; pointer <= input.end() && url.is_valid; pointer++) {
      parseState();
    }
  }

  void Parser::parseState() {
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
            if (pointer + 2 < input.end() && pointer[1] == '/' && pointer[2] == '/') {
              url.has_validation_error = true;
            }
            // Set state to file state.
            state = FILE;
          }
          // Otherwise, if url is special, base is non-null, and base’s scheme is url’s scheme:
          else if (url.is_special() && base_url.has_value() && base_url->scheme == url.scheme) {
            // Assert: base is is special (and therefore does not have an opaque path).
            assert(base_url->is_special()); // TODO: Check to disable assert on release builds.

            // Set state to special relative or authority state.
            state = SPECIAL_RELATIVE_OR_AUTHORITY;
          }
          // Otherwise, if url is special, set state to special authority slashes state.
          else if (url.is_special()) {
            state = SPECIAL_AUTHORITY_SLASHES;
          }
          // Otherwise, if remaining starts with an U+002F (/), set state to path or authority state
          // and increase pointer by 1.
          else if (pointer + 1 < input.end() && pointer[1] == '/') {
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
          pointer = input.begin();
          pointer--;
        }
        // Otherwise, validation error, return failure.
        else {
          url.has_validation_error = true;
          url.is_valid = false;
        }
      }
      default:
        printf("not implemented");
    }
  }

  ada::URL Parser::getURL() {
    return url;
  }

} // namespace ada
