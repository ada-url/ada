#include "ada.h"
#include "unicode.cpp"
#include "parser.h"

#include <cctype>

namespace ada {

  Parser::Parser(std::string_view input, std::optional<ada::URL> optional_base_url, std::optional<ada::encoding_type> encoding_override,
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
      default:
        printf("not implemented");
    }
  }

  ada::URL Parser::getURL() {
    return url;
  }

} // namespace ada
