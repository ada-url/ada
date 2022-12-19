#include "ada.h"
#include "parser.h"

namespace ada {

  Parser::Parser(const std::string_view input, std::optional<ada::URL> optional_base_url, 
                 std::optional<ada::encoding_type> encoding_override,
                 std::optional<ada::state> state_override) :
                    buffer{}, pointer{input.begin()},
                    encoding{encoding_override.value_or(ada::encoding_type::UTF8)},
                    state{state_override.value_or(SCHEME_START)},
                    base_url{optional_base_url} {

    // TODO: If input contains any leading or trailing C0 control or space, validation error.
    // TODO: Remove any leading and trailing C0 control or space from input.

    // TODO: If input contains any ASCII tab or newline, validation error.
    // TODO: Remove all ASCII tab or newline from input.
    // Keep running the following state machine by switching on state.
    // If after a run pointer points to the EOF code point, go to the next step.
    // Otherwise, increase pointer by 1 and continue with the state machine.
    for (; pointer <= input.end(); pointer++) {
      parseState();
    }
  }

  void Parser::parseState() {
    // TODO: Implement this.
  }

  ada::URL Parser::getURL() {
    return url;
  }

} // namespace ada
