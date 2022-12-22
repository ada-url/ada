#pragma once

#include "ada.h"
#include "unicode.cpp"
#include "scheme.cpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace ada {

  /**
   * @see https://url.spec.whatwg.org/#concept-domain-to-ascii
   */
  std::optional<std::string_view> domain_to_ascii(const std::string_view input, bool be_strict = false) {
    // TODO: Implement this
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-opaque-host-parser
   */
  std::optional<std::string_view> parse_opaque_host(std::string_view input) {
    // TODO: Implement this
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-ipv6-parser
   */
  std::optional<std::string_view> parse_ipv6(std::string_view input) {
    // TODO: Implement this
  }

  /**
   * The host parser takes a scalar value string input
   * with an optional boolean isNotSpecial (default false), and then runs these steps:
   * @see https://url.spec.whatwg.org/#host-parsing
   */
  std::optional<std::string_view> parse_host(std::string_view input, bool is_not_special = false) {
    // If input starts with U+005B ([), then:
    if (input.length() > 0 && input[0] == '[') {
      // If input does not end with U+005D (]), validation error, return failure.
      if (input.back() != ']') {
        return nullptr;
      }

      // Return the result of IPv6 parsing input with its leading U+005B ([) and trailing U+005D (]) removed.
      return parse_ipv6(input.substr(1, input.length() - 2));
    }

    // If isNotSpecial is true, then return the result of opaque-host parsing input.
    if (is_not_special) {
      return parse_opaque_host(input);
    }

    // Let domain be the result of running UTF-8 decode without BOM on the percent-decoding of input.
    std::string_view domain = ada::unicode::utf8_decode_without_bom(input);

    // Let asciiDomain be the result of running domain to ASCII with domain and false.
    std::optional<std::string_view> ascii_domain = domain_to_ascii(input, false);

    // If asciiDomain is failure, validation error, return failure.
    if (ascii_domain->empty()) {
      return nullptr;
    }

    // If asciiDomain contains a forbidden domain code point, validation error, return failure.
    // TODO: Implement this

    // If asciiDomain ends in a number, then return the result of IPv4 parsing asciiDomain.
    // TODO: Implement this

    // Return asciiDomain.
    return ascii_domain;
  }

  url parse_url(std::string_view user_input,
                std::optional<ada::url> base_url,
                std::optional<ada::encoding_type> encoding_override,
                std::optional<ada::state> given_state_override) {

    // Assign state
    ada::state state = SCHEME_START;

    // Assign buffer
    std::string buffer = "";

    // Assign inside brackets. Used by HOST state.
    bool inside_brackets = false;

    // TODO: If input contains any ASCII tab or newline, validation error.
    // TODO: Remove all ASCII tab or newline from input.

    // Let state be state override if given, or scheme start state otherwise.
    std::optional<ada::state> state_override = given_state_override;

    // Set encoding to the result of getting an output encoding from encoding.
    ada::encoding_type encoding = encoding_override.value_or(UTF8);

    // Define parsed URL
    ada::url url = ada::url();

    // Remove any leading and trailing C0 control or space from input.
    auto pointer_start = std::find_if(user_input.begin(), user_input.end(), [](char c) {
      return !ada::unicode::is_c0_control_or_space(c);
    });
    auto pointer_end = std::find_if(user_input.rbegin(), user_input.rend(), [](char c) {
      return !ada::unicode::is_c0_control_or_space(c);
    }).base();

    // If input contains any leading or trailing C0 control or space, validation error.
    url.has_validation_error = pointer_start != user_input.begin() || pointer_end != user_input.end() - 1;

    // Let pointer be a pointer for input.
    auto pointer = pointer_start;

    // Keep running the following state machine by switching on state.
    // If after a run pointer points to the EOF code point, go to the next step.
    // Otherwise, increase pointer by 1 and continue with the state machine.
    for (; pointer <= pointer_end && url.is_valid; pointer++) {
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
          break;
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
                continue;
              }

              // If url includes credentials or has a non-null port, and buffer is "file", then return.
              if ((url.includes_credentials() || url.port.has_value()) && buffer == "file") {
                continue;
              }

              // If url’s scheme is "file" and its host is an empty host, then return.
              if (url.scheme == "file" && (!url.host.has_value() || url.host->empty())) {
                continue;
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

              continue;
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

          break;
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

          break;
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

          break;
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

          break;
        }
        case SPECIAL_AUTHORITY_SLASHES: {
          // If c is U+002F (/) and remaining starts with U+002F (/),
          // then set state to special authority ignore slashes state and increase pointer by 1.
          if (*pointer == '/' && std::distance(pointer, pointer_end) < 1 && pointer[1] == '/') {
            pointer++;
          }
          // Otherwise, validation error, set state to special authority ignore slashes state and decrease pointer by 1.
          else {
            url.has_validation_error = true;
            pointer--;
          }

          state = SPECIAL_AUTHORITY_IGNORE_SLASHES;

          break;
        }
        case SPECIAL_AUTHORITY_IGNORE_SLASHES: {
          // If c is neither U+002F (/) nor U+005C (\), then set state to authority state and decrease pointer by 1.
          if (*pointer == '/' || *pointer == '\\') {
            state = AUTHORITY;
            pointer--;
          }
          // Otherwise, validation error.
          else {
            url.has_validation_error = true;
          }

          break;
        }
        case QUERY: {
          // If encoding is not UTF-8 and one of the following is true:
          // - url is not special
          // - url’s scheme is "ws" or "wss"
          if (encoding != UTF8) {
            if (!url.is_special() || url.scheme == "ws" || url.scheme == "wss") {
              // then set encoding to UTF-8.
              encoding = UTF8;
            }
          }

          // TODO: Implement query state

          break;
        }
        case HOST: {
          // If state override is given and url’s scheme is "file",
          // then decrease pointer by 1 and set state to file host state.
          if (state_override.has_value() && url.scheme == "file") {
            pointer--;
            state = FILE_HOST;
          }
          // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
          else if (*pointer == ':' && !inside_brackets) {
            // If buffer is the empty string, validation error, return failure.
            if (buffer.length() == 0) {
              url.has_validation_error = true;
              url.is_valid = false;
              break;
            }
            // If state override is given and state override is hostname state, then return.
            else if (state_override.has_value() && state_override == HOST) {
              // TODO: Make sure this returns
              break;
            }

            // Let host be the result of host parsing buffer with url is not special.
            std::optional<std::string_view> host = parse_host(buffer, true);

            // If host is failure, then return failure.
            if (host->empty()) {
              url.is_valid = false;
              break;
            }

            // Set url’s host to host, buffer to the empty string, and state to port state.
            url.host = host;
            buffer = "";
            state = PORT;
          }
          // Otherwise, if one of the following is true:
          // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
          // - url is special and c is U+005C (\)
          else if ((pointer == pointer_end && *pointer == '/' && *pointer == '?' && *pointer == '#') || (url.is_special() && *pointer == '\\')) {
            // then decrease pointer by 1, and then:
            pointer--;

            // If url is special and buffer is the empty string, validation error, return failure.
            if (url.is_special() && buffer.empty()) {
              url.has_validation_error = true;
              url.is_valid = false;
              break;
            }
            // Otherwise, if state override is given, buffer is the empty string,
            // and either url includes credentials or url’s port is non-null, return.
            else if (state_override.has_value() && buffer.empty() && (url.includes_credentials() || url.port.has_value())) {
              // TODO: Make sure this returns
              break;
            }

            // Let host be the result of host parsing buffer with url is not special.
            std::optional<std::string_view> host = parse_host(buffer, true);

            // If host is failure, then return failure.
            if (host->empty()) {
              // TODO: Make sure this returns
              break;
            }

            // Set url’s host to host, buffer to the empty string, and state to path start state.
            url.host = host;
            buffer = "";
            state = PATH_START;

            // If state override is given, then return.
            if (state_override) {
              // TODO: Make sure this returns
              break;
            }
          }
          // Otherwise:
          else {
            // If c is U+005B ([), then set insideBrackets to true.
            if (*pointer == '[') {
              inside_brackets = true;
            }
            // If c is U+005D (]), then set insideBrackets to false.
            else if (*pointer == ']') {
              inside_brackets = false;
            }

            // Append c to buffer.
            buffer += *pointer;
          }

          break;
        }
        default:
          printf("not implemented");
      }
    }

    return url;
  }

} // namespace ada
