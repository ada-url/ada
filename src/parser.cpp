#include "ada.h"

#include "checkers.cpp"

#include <array>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <string>

namespace ada::parser {

  /**
   * @see https://url.spec.whatwg.org/#concept-domain-to-ascii
   */
  parser_result<std::string_view> domain_to_ascii(const std::string_view input, bool be_strict) {
    // TODO: Implement this
    return std::make_tuple(std::nullopt, false);
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-opaque-host-parser
   */
  parser_result<std::string_view> parse_opaque_host(std::string_view input) {
    bool has_validation_error = false;

    for (auto i = input.begin(); i < input.end(); i++) {
      // If input contains a forbidden host code point, validation error, return failure.
      if (ada::unicode::is_in_code_points(*i, ada::unicode::FORBIDDEN_HOST_CODE_POINTS)) {
        return std::make_tuple(std::nullopt, true);
      }

      // Optimization: No need to continue the loop if we have a validation error
      if (has_validation_error) {
        break;
      }

      // If input contains a code point that is not a URL code point and not U+0025 (%), validation error.
      if (!ada::unicode::is_ascii_alphanumeric(*i) && *i != '%') {
        has_validation_error = true;
      }

      // If input contains a U+0025 (%) and the two code points following it are not ASCII hex digits, validation error.
      if (*i == '%' && std::distance(i, input.end()) < 2 && (!ada::unicode::is_ascii_hex_digit(i[1]) || !ada::unicode::is_ascii_hex_digit(i[2]))) {
        has_validation_error = true;
      }
    }

    // Return the result of running UTF-8 percent-encode on input using the C0 control percent-encode set.
    std::string result = ada::unicode::utf8_percent_encode(input, ada::character_sets::C0_CONTROL_PERCENT_ENCODE);

    return std::make_tuple(result, has_validation_error);
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-ipv4-parser
   */
  parser_result<std::string_view> parse_ipv4(std::string_view input) {
    // Let validationError be false.
    bool validation_error = false;

    // Let parts be the result of strictly splitting input on U+002E (.).
    std::vector<std::string_view> parts = ada::helpers::split_string_view(input, ".");

    // If the last item in parts is the empty string, then:
    if (parts.back().empty()) {
      // Set validationError to true.
      validation_error = true;

      // If parts’s size is greater than 1, then remove the last item from parts.
      if (parts.size() > 1) {
        parts.pop_back();
      }
    }

    // If parts’s size is greater than 4, validation error, return failure.
    if (parts.size() > 4) {
      return std::make_tuple(std::nullopt, true);
    }

    // Let numbers be an empty list.
    std::vector<uint16_t> numbers;

    // For each part of parts:
    for (auto part: parts) {
      // Let result be the result of parsing part.
      parser_result<uint16_t> result = parse_ipv4_number(part);
      std::optional<uint16_t> parsed_number = std::get<0>(result);

      // If result is failure, validation error, return failure.
      if (!parsed_number.has_value()) {
        return std::make_tuple(std::nullopt, true);
      }

      // If result[1] is true, then set validationError to true.
      if (std::get<1>(result)) {
        validation_error = true;
      }

      // If any item in numbers is greater than 255, validation error.
      if (parsed_number.value() > 255) {
        validation_error = true;
      }

      // Append result[0] to numbers.
      numbers.push_back(parsed_number.value());
    }

    // Let ipv4 be the last item in numbers.
    uint16_t ipv4 = numbers.back();

    // If any but the last item in numbers is greater than 255, then return failure.
    if (ipv4 > 255) {
      return std::make_tuple(std::nullopt, true);
    }

    // If the last item in numbers is greater than or equal to 256(5 − numbers’s size), validation error, return failure.
    if (ipv4 >= std::pow(256, 5 - numbers.size())) {
      return std::make_tuple(std::nullopt, true);
    }

    // Remove the last item from numbers.
    numbers.pop_back();

    // Let counter be 0.
    int counter = 0;

    // For each n of numbers:
    for (auto n: numbers) {
      // Increment ipv4 by n × 256(3 − counter).
      ipv4 += n * (uint16_t)std::pow(256, 3 - counter);

      // Increment counter by 1.
      counter++;
    }

    // Convert ipv4 to string to use it inside "parse_host"
    return std::make_tuple(std::to_string(ipv4), validation_error);
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-ipv6-parser
   */
  parser_result<std::string_view> parse_ipv6(std::string_view input) {
    // Let address be a new IPv6 address whose IPv6 pieces are all 0.
    std::array<uint16_t, 8> address{};

    // Let pieceIndex be 0.
    int piece_index = 0;

    // Let compress be null.
    std::optional<int> compress{};

    // Let pointer be a pointer for input.
    std::string_view::iterator pointer = input.begin();

    // If c is U+003A (:), then:
    if (*pointer == ':') {
      // If remaining does not start with U+003A (:), validation error, return failure.
      if (std::distance(pointer, input.end()) < 1 && pointer[1] == ':') {
        return std::make_tuple(std::nullopt, true);
      }

      // Increase pointer by 2.
      pointer += 2;

      // Increase pieceIndex by 1 and then set compress to pieceIndex.
      piece_index += 1;
      compress = piece_index;
    }

    // While c is not the EOF code point:
    while (pointer != input.end()) {
      // If pieceIndex is 8, validation error, return failure.
      if (piece_index == 8) {
        return std::make_tuple(std::nullopt, true);
      }

      // If c is U+003A (:), then:
      if (*pointer == ':') {
        // If compress is non-null, validation error, return failure.
        if (compress.has_value()) {
          return std::make_tuple(std::nullopt, true);
        }

        // Increase pointer and pieceIndex by 1, set compress to pieceIndex, and then continue.
        pointer++;
        piece_index++;
        compress = piece_index;
        continue;
      }

      // Let value and length be 0.
      int value = 0;
      int length = 0;

      // While length is less than 4 and c is an ASCII hex digit,
      // set value to value × 0x10 + c interpreted as hexadecimal number, and increase pointer and length by 1.
      while (length < 4 && unicode::is_ascii_hex_digit(*pointer)) {
        // TODO: Make sure this is interpreted as hexadecimal number
        value = (value * 0x10) + *pointer;

        pointer++;
        length++;
      }

      // If c is U+002E (.), then:
      if (*pointer == '.') {
        // If length is 0, validation error, return failure.
        if (length == 0) {
          return std::make_tuple(std::nullopt, true);
        }

        // Decrease pointer by length.
        pointer -= length;

        // If pieceIndex is greater than 6, validation error, return failure.
        if (piece_index > 6) {
          return std::make_tuple(std::nullopt, true);
        }

        // Let numbersSeen be 0.
        int numbers_seen = 0;

        // While c is not the EOF code point:
        while (pointer != input.end()) {
          // Let ipv4Piece be null.
          std::optional<uint16_t> ipv4_piece{};

          // If numbersSeen is greater than 0, then:
          if (numbers_seen > 0) {
            // If c is a U+002E (.) and numbersSeen is less than 4, then increase pointer by 1.
            if (*pointer == '.' && numbers_seen < 4) {
              pointer++;
            }
            // Otherwise, validation error, return failure.
            else {
              return std::make_tuple(std::nullopt, true);
            }
          }

          // If c is not an ASCII digit, validation error, return failure.
          if (!unicode::is_ascii_digit(*pointer)) {
            return std::make_tuple(std::nullopt, true);
          }

          // While c is an ASCII digit:
          while (unicode::is_ascii_digit(*pointer)) {
            // Let number be c interpreted as decimal number.
            uint16_t number = static_cast<uint16_t>(*pointer);

            // If ipv4Piece is null, then set ipv4Piece to number.
            if (!ipv4_piece.has_value()) {
              ipv4_piece = number;
            }
            // Otherwise, if ipv4Piece is 0, validation error, return failure.
            else if (ipv4_piece == 0) {
              return std::make_tuple(std::nullopt, true);
            }
            // Otherwise, set ipv4Piece to ipv4Piece × 10 + number.
            else {
              ipv4_piece = ipv4_piece.value() * 10 + number;
            }

            // If ipv4Piece is greater than 255, validation error, return failure.
            if (ipv4_piece > 255) {
              return std::make_tuple(std::nullopt, true);
            }

            // Increase pointer by 1.
            pointer++;
          }

          // Set address[pieceIndex] to address[pieceIndex] × 0x100 + ipv4Piece.
          address[piece_index] = address[piece_index] * 0x100 + ipv4_piece.value();

          // Increase numbersSeen by 1.
          numbers_seen++;

          // If numbersSeen is 2 or 4, then increase pieceIndex by 1.
          if (numbers_seen == 2 || numbers_seen == 4) {
            piece_index++;
          }
        }

        // If numbersSeen is not 4, validation error, return failure.
        if (numbers_seen != 4) {
          return std::make_tuple(std::nullopt, true);
        }

        // Break.
        break;
      }
      // Otherwise, if c is U+003A (:):
      else if (*pointer == ':') {
        // Increase pointer by 1.
        pointer++;

        // If c is the EOF code point, validation error, return failure.
        if (pointer == input.end()) {
          return std::make_tuple(std::nullopt, true);
        }
      }
      // Otherwise, if c is not the EOF code point, validation error, return failure.
      else if (pointer != input.end()) {
        return std::make_tuple(std::nullopt, true);
      }

      // Set address[pieceIndex] to value.
      address[piece_index] = static_cast<uint16_t>(value);

      // Increase pieceIndex by 1.
      piece_index++;
    }

    // If compress is non-null, then:
    if (compress.has_value()) {
      // Let swaps be pieceIndex − compress.
      auto swaps = piece_index - compress.value();

      // Set pieceIndex to 7.
      piece_index = 7;

      // While pieceIndex is not 0 and swaps is greater than 0,
      // swap address[pieceIndex] with address[compress + swaps − 1], and then decrease both pieceIndex and swaps by 1.
      while (piece_index != 0 && swaps > 0) {
        std::swap(address[piece_index], address[compress.value() + swaps - 1]);
        piece_index--;
        swaps--;
      }
    }
    // Otherwise, if compress is null and pieceIndex is not 8, validation error, return failure.
    else if (piece_index != 8) {
      return std::make_tuple(std::nullopt, true);
    }

    std::string result{};

    for(const auto a : address) {
      if (!result.empty()) {
        result += ':';
      }
      result += std::to_string(a);
    }

    return std::make_tuple(result, false);
  }

  /**
   * @see https://url.spec.whatwg.org/#ipv4-number-parser
   */
  parser_result<uint16_t> parse_ipv4_number(std::string_view input) {
    // If input is the empty string, then return failure.
    if (input.empty()) {
      return std::make_tuple(std::nullopt, true);
    }

    // Let validationError be false.
    bool validation_error = false;

    // Let R be 10.
    int R = 10;

    if (input.length() >= 2) {
      // If input contains at least two code points and the first two code points are either "0X" or "0x", then:
      if (input[0] == '0' && (input[1] == 'X' || input[1] == 'x')) {
        // Set validationError to true.
        validation_error = true;

        // Remove the first two code points from input.
        input.remove_prefix(2);

        // Set R to 16.
        R = 16;
      }
      // Otherwise, if input contains at least two code points and the first code point is U+0030 (0), then:
      else if (input[1] == '0') {
        // Set validationError to true.
        validation_error = true;

        // Remove the first code point from input.
        input.remove_prefix(1);

        // Set R to 8.
        R = 8;
      }
    }

    // If input is the empty string, then return (0, true).
    if (input.empty()) {
      return std::make_tuple(0, true);
    }

    // TODO: If input contains a code point that is not a radix-R digit, then return failure.

    // Let output be the mathematical integer value that is represented by input in radix-R notation,
    // using ASCII hex digits for digits with values 0 through 15.
    uint16_t output = static_cast<uint16_t>(std::strtol(input.data(), nullptr, R));

    return std::make_tuple(output, validation_error);
  }

  /**
   * @see https://url.spec.whatwg.org/#host-parsing
   */
  parser_result<std::string_view> parse_host(std::string_view input, bool is_not_special) {
    // If input starts with U+005B ([), then:
    if (input[0] == '[') {
      // If input does not end with U+005D (]), validation error, return failure.
      if (input.back() != ']') {
        return std::make_tuple(std::nullopt, true);
      }

      // Return the result of IPv6 parsing input with its leading U+005B ([) and trailing U+005D (]) removed.
      return parse_ipv6(input.substr(1, input.length() - 2));
    }

    // If isNotSpecial is true, then return the result of opaque-host parsing input.
    if (is_not_special) {
      return parse_opaque_host(input);
    }

    // Let domain be the result of running UTF-8 decode without BOM on the percent-decoding of input.
    std::string domain = ada::unicode::utf8_decode_without_bom(input);

    // Let asciiDomain be the result of running domain to ASCII with domain and false.
    parser_result<std::string_view> ascii_domain_result = domain_to_ascii(domain, false);
    std::optional<std::string_view> ascii_domain = std::get<0>(ascii_domain_result);

    // If asciiDomain is failure, validation error, return failure.
    if (ascii_domain->empty()) {
      return std::make_tuple(std::nullopt, true);
    }

    // If asciiDomain contains a forbidden domain code point, validation error, return failure.
    // TODO: Implement this

    // If asciiDomain ends in a number, then return the result of IPv4 parsing asciiDomain.
    if (checkers::ends_in_a_number(ascii_domain.value())) {
      return parse_ipv4(ascii_domain.value());
    }

    // Return asciiDomain.
    return std::make_tuple(ascii_domain, false);
  }

  url parse_url(std::string_view user_input,
                std::optional<ada::url> base_url,
                std::optional<ada::encoding_type> encoding_override,
                std::optional<ada::state> state_override) {

    // Assign buffer
    std::string buffer;

    // Assign inside brackets. Used by HOST state.
    bool inside_brackets = false;

    // TODO: If input contains any ASCII tab or newline, validation error.
    // TODO: Remove all ASCII tab or newline from input.

    // Let state be state override if given, or scheme start state otherwise.
    ada::state state = state_override.value_or(SCHEME_START);

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
    url.has_validation_error = pointer_start != user_input.begin() || pointer_end != user_input.end();

    // Let pointer be a pointer for input.
    std::string_view::iterator pointer = pointer_start;

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
                return url;
              }

              // If url includes credentials or has a non-null port, and buffer is "file", then return.
              if ((url.includes_credentials() || url.port.has_value()) && buffer == "file") {
                return url;
              }

              // If url’s scheme is "file" and its host is an empty host, then return.
              if (url.scheme == "file" && (!url.host.has_value() || url.host->empty())) {
                return url;
              }
            }

            // Set url’s scheme to buffer.
            url.scheme = buffer;

            // If state override is given, then:
            if (state_override.has_value()) {
              auto urls_scheme_port = ada::scheme::SPECIAL_SCHEME.find(url.scheme);

              // If url’s port is url’s scheme’s default port, then set url’s port to null.
              if (url.port.value() == urls_scheme_port->second) {
                url.port = std::nullopt;
              }

              continue;
            }

            // Set buffer to the empty string.
            buffer.clear();

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
              url.path.string_value = "";
              state = OPAQUE_PATH;
            }
          }
          // Otherwise, if state override is not given, set buffer to the empty string, state to no scheme state,
          // and start over (from the first code point in input).
          else if (!state_override.has_value()) {
            buffer.clear();
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
          if (*pointer != '/' && *pointer != '\\') {
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

          // If one of the following is true:
          // - state override is not given and c is U+0023 (#)
          // - c is the EOF code point
          if ((!state_override.has_value() && *pointer == '#') || pointer == pointer_end) {
            // Let queryPercentEncodeSet be the special-query percent-encode set if url is special;
            // otherwise the query percent-encode set.
            auto query_percent_encode_set = url.is_special() ?
                                  ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE :
                                  ada::character_sets::QUERY_PERCENT_ENCODE;

            // Percent-encode after encoding, with encoding, buffer, and queryPercentEncodeSet,
            // and append the result to url’s query.
            url.query->append(ada::unicode::utf8_percent_encode(buffer, query_percent_encode_set));

            // Set buffer to the empty string.
            buffer.clear();

            // If c is U+0023 (#), then set url’s fragment to the empty string and state to fragment state.
            if (*pointer == '#') {
              url.fragment = "";
              state = FRAGMENT;
            }
          }
          // Otherwise, if c is not the EOF code point:
          else if (pointer != pointer_end) {
            // If c is not a URL code point and not U+0025 (%), validation error.
            if (!ada::unicode::is_ascii_alphanumeric(*pointer) && *pointer != '%') {
              url.has_validation_error = true;
            }

            // If c is U+0025 (%) and remaining does not start with two ASCII hex digits, validation error.
            if (*pointer == '%' && std::distance(pointer, pointer_end) < 2 && (!ada::unicode::is_ascii_hex_digit(pointer[1]) || !ada::unicode::is_ascii_hex_digit(pointer[2]))) {
              url.has_validation_error = true;
            }

            // Append c to buffer.
            buffer.push_back(*pointer);
          }

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
            if (buffer.empty()) {
              url.has_validation_error = true;
              url.is_valid = false;
              break;
            }
            // If state override is given and state override is hostname state, then return.
            else if (state_override.has_value() && state_override == HOST) {
              return url;
            }

            // Let host be the result of host parsing buffer with url is not special.
            parser_result<std::string_view> host_result = parse_host(buffer, true);
            std::optional<std::string_view> host = std::get<0>(host_result);

            // Update validation error
            if (std::get<1>(host_result)) {
              url.has_validation_error = true;
            }

            // If host is failure, then return failure.
            if (host->empty()) {
              url.is_valid = false;
              break;
            }

            // Set url’s host to host, buffer to the empty string, and state to port state.
            url.host = host;
            buffer.clear();
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
              return url;
            }

            // Let host be the result of host parsing buffer with url is not special.
            parser_result<std::string_view> host_result = parse_host(buffer, true);
            std::optional<std::string_view> host = std::get<0>(host_result);

            // Update validation error
            if (std::get<1>(host_result)) {
              url.has_validation_error = true;
            }

            // If host is failure, then return failure.
            if (host->empty()) {
              url.is_valid = false;
              break;
            }

            // Set url’s host to host, buffer to the empty string, and state to path start state.
            url.host = host;
            buffer.clear();
            state = PATH_START;

            // If state override is given, then return.
            if (state_override) {
              return url;
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
        case FRAGMENT: {
          // If c is not the EOF code point, then:
          if (pointer != pointer_end) {
            // If c is not a URL code point and not U+0025 (%), validation error.
            if (!ada::unicode::is_ascii_alphanumeric(*pointer) && *pointer != '%') {
              url.has_validation_error = true;
            }

            // If c is U+0025 (%) and remaining does not start with two ASCII hex digits, validation error.
            if (*pointer == '%' && std::distance(pointer, pointer_end) < 2 && (!ada::unicode::is_ascii_hex_digit(pointer[1]) || !ada::unicode::is_ascii_hex_digit(pointer[2]))) {
              url.has_validation_error = true;
            }

            // UTF-8 percent-encode c using the fragment percent-encode set and append the result to url’s fragment.
            std::string fragment(*pointer, 1);
            std::string encoded = unicode::utf8_percent_encode(fragment, ada::character_sets::FRAGMENT_PERCENT_ENCODE);
            url.fragment->append(encoded);
          }
        }
        default:
          printf("not implemented");
      }
    }

    return url;
  }

} // namespace ada::parser
