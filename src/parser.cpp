#include "ada.h"
#include "parser.h"

namespace ada {

  Parser::Parser(const char *input, std::optional<ada::URL> optional_base_url, std::optional<ada::encoding_type> encoding_override,
                 std::optional<ada::state> state_override) {
    // Assign base_url if it exists
    base_url = optional_base_url;

    // TODO: If input contains any leading or trailing C0 control or space, validation error.
    // TODO: Remove any leading and trailing C0 control or space from input.

    // TODO: If input contains any ASCII tab or newline, validation error.
    // TODO: Remove all ASCII tab or newline from input.

    // Let state be state override if given, or scheme start state otherwise.
    if (state_override.has_value()) {
      state = state_override.value();
    }

    // Set encoding to the result of getting an output encoding from encoding.
    if (encoding_override.has_value()) {
      encoding = encoding_override.value();
    }

    // Let pointer be a pointer for input.
    pointer = const_cast<char*>(input);

    // Define parsed URL
    url = ada::URL();

    // Keep running the following state machine by switching on state.
    // If after a run pointer points to the EOF code point, go to the next step.
    // Otherwise, increase pointer by 1 and continue with the state machine.
    for (; *pointer != '\0'; pointer++) {
      parseState();
    }

    // Run parseState one more time since it should run with EOF code point.
    parseState();
  }

  void Parser::parseState() {
    // TODO: Implement this.
  }

  ada::URL Parser::getURL() {
    return url;
  }

} // namespace ada
