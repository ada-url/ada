#include "ada.h"

#include "checkers.cpp"

#include <array>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cmath>
#include <cstdlib>

namespace ada::parser {

  /**
   * @see https://url.spec.whatwg.org/#concept-domain-to-ascii
   */
  bool domain_to_ascii(const std::string_view input) {
    for (auto pointer: input) {
      if (unicode::is_ascii_upper_alpha(pointer)) {
        pointer += 32;
      }
    }

    return false;
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-opaque-host-parser
   */
  std::optional<std::string_view> parse_opaque_host(std::string_view input) {
    for (auto i = input.begin(); i < input.end(); i++) {
      // If input contains a forbidden host code point, validation error, return failure.
      // TODO: Replace this with .contains after moving to C++ 20.
      if (ada::unicode::FORBIDDEN_HOST_CODE_POINTS.count(*i)) {
        return std::nullopt;
      }
    }

    // Return the result of running UTF-8 percent-encode on input using the C0 control percent-encode set.
    return ada::unicode::utf8_percent_encode(input, ada::character_sets::C0_CONTROL_PERCENT_ENCODE);
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-ipv4-parser
   */
  std::optional<std::string_view> parse_ipv4(std::string_view input) {
    // Let parts be the result of strictly splitting input on U+002E (.).
    std::vector<std::string_view> parts = ada::helpers::split_string_view(input, ".");

    // If the last item in parts is the empty string, then:
    if (parts.back().empty()) {
      // If parts’s size is greater than 1, then remove the last item from parts.
      if (parts.size() > 1) {
        parts.pop_back();
      }
    }

    // If parts’s size is greater than 4, validation error, return failure.
    if (parts.size() > 4) {
      return std::nullopt;
    }

    // Let numbers be an empty list.
    std::vector<uint16_t> numbers;

    // For each part of parts:
    for (auto part: parts) {
      // Let result be the result of parsing part.
      std::optional<uint16_t> result = parse_ipv4_number(part);

      // If result is failure, validation error, return failure.
      if (!result.has_value()) {
        return std::nullopt;
      }

      // If any but the last item in numbers is greater than 255, then return failure.
      if (*result > 255 && part != parts.back()) {
        return std::nullopt;
      }

      // Append result[0] to numbers.
      numbers.push_back(*result);
    }

    // Let ipv4 be the last item in numbers.
    uint16_t ipv4 = numbers.back();

    // If the last item in numbers is greater than or equal to 256(5 − numbers’s size), validation error, return failure.
    if (ipv4 >= std::pow(256, 5 - numbers.size())) {
      return std::nullopt;
    }

    // Remove the last item from numbers.
    numbers.pop_back();

    // Let counter be 0.
    auto counter = 0;

    // For each n of numbers:
    for (auto n: numbers) {
      // Increment ipv4 by n × 256(3 − counter).
      ipv4 += static_cast<uint16_t>(n * std::pow(256, 3 - counter));

      // Increment counter by 1.
      counter++;
    }

    // Convert ipv4 to string to use it inside "parse_host"
    return std::to_string(ipv4);
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-ipv6-parser
   */
  std::optional<std::string_view> parse_ipv6(std::string_view input) {
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
        return std::nullopt;
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
        return std::nullopt;
      }

      // If c is U+003A (:), then:
      if (*pointer == ':') {
        // If compress is non-null, validation error, return failure.
        if (compress.has_value()) {
          return std::nullopt;
        }

        // Increase pointer and pieceIndex by 1, set compress to pieceIndex, and then continue.
        pointer++;
        piece_index++;
        compress = piece_index;
        continue;
      }

      // Let value and length be 0.
      long value = 0;
      long length = 0;

      // While length is less than 4 and c is an ASCII hex digit,
      // set value to value × 0x10 + c interpreted as hexadecimal number, and increase pointer and length by 1.
      while (length < 4 && unicode::is_ascii_hex_digit(*pointer)) {
        value = (value * 0x10) + std::strtol(pointer, nullptr, 16);
        pointer++;
        length++;
      }

      // If c is U+002E (.), then:
      if (*pointer == '.') {
        // If length is 0, validation error, return failure.
        if (length == 0) {
          return std::nullopt;
        }

        // Decrease pointer by length.
        pointer -= length;

        // If pieceIndex is greater than 6, validation error, return failure.
        if (piece_index > 6) {
          return std::nullopt;
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
              return std::nullopt;
            }
          }

          // If c is not an ASCII digit, validation error, return failure.
          if (!std::isdigit(*pointer)) {
            return std::nullopt;
          }

          // While c is an ASCII digit:
          while (std::isdigit(*pointer)) {
            // Let number be c interpreted as decimal number.
            int number = *pointer - '0';

            // If ipv4Piece is null, then set ipv4Piece to number.
            if (!ipv4_piece.has_value()) {
              ipv4_piece = number;
            }
            // Otherwise, if ipv4Piece is 0, validation error, return failure.
            else if (ipv4_piece == 0) {
              return std::nullopt;
            }
            // Otherwise, set ipv4Piece to ipv4Piece × 10 + number.
            else {
              ipv4_piece = *ipv4_piece * 10 + number;
            }

            // If ipv4Piece is greater than 255, validation error, return failure.
            if (ipv4_piece > 255) {
              return std::nullopt;
            }

            // Increase pointer by 1.
            pointer++;
          }

          // Set address[pieceIndex] to address[pieceIndex] × 0x100 + ipv4Piece.
          address[piece_index] = static_cast<uint16_t>(address[piece_index] * 0x100) + *ipv4_piece;

          // Increase numbersSeen by 1.
          numbers_seen++;

          // If numbersSeen is 2 or 4, then increase pieceIndex by 1.
          if (numbers_seen == 2 || numbers_seen == 4) {
            piece_index++;
          }
        }

        // If numbersSeen is not 4, validation error, return failure.
        if (numbers_seen != 4) {
          return std::nullopt;
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
          return std::nullopt;
        }
      }
      // Otherwise, if c is not the EOF code point, validation error, return failure.
      else if (pointer != input.end()) {
        return std::nullopt;
      }

      // Set address[pieceIndex] to value.
      address[piece_index] = static_cast<uint16_t>(value);

      // Increase pieceIndex by 1.
      piece_index++;
    }

    // If compress is non-null, then:
    if (compress.has_value()) {
      // Let swaps be pieceIndex − compress.
      auto swaps = piece_index - *compress;

      // Set pieceIndex to 7.
      piece_index = 7;

      // While pieceIndex is not 0 and swaps is greater than 0,
      // swap address[pieceIndex] with address[compress + swaps − 1], and then decrease both pieceIndex and swaps by 1.
      while (piece_index != 0 && swaps > 0) {
        std::swap(address[piece_index], address[*compress + swaps - 1]);
        piece_index--;
        swaps--;
      }
    }
    // Otherwise, if compress is null and pieceIndex is not 8, validation error, return failure.
    else if (piece_index != 8) {
      return std::nullopt;
    }

    std::string result{};

    for (const auto a : address) {
      if (!result.empty()) {
        result += ':';
      }
      result += std::to_string(a);
    }

    return result;
  }

  /**
   * @see https://url.spec.whatwg.org/#ipv4-number-parser
   */
  std::optional<uint16_t> parse_ipv4_number(std::string_view input) {
    // If input is the empty string, then return failure.
    if (input.empty()) {
      return std::nullopt;
    }

    // Let R be 10.
    int R = 10;

    // Allowed characters
    char allowed_characters[23] = "0123456789";

    if (input.length() >= 2) {
      // If input contains at least two code points and the first two code points are either "0X" or "0x", then:
      if (input[0] == '0' && (input[1] == 'X' || input[1] == 'x')) {
        // Remove the first two code points from input.
        input.remove_prefix(2);

        // Set R to 16.
        R = 16;

        // Update allowed characters
        std::strcpy(allowed_characters, "0123456789abcdefABCDEF");
      }
      // Otherwise, if input contains at least two code points and the first code point is U+0030 (0), then:
      else if (input[1] == '0') {
        // Remove the first code point from input.
        input.remove_prefix(1);

        // Set R to 8.
        R = 8;
      }

      // If input is the empty string, then return (0, true).
      if (input.empty()) {
        return 0;
      }
    }

    // If input contains a code point that is not a radix-R digit, then return failure.
    if (std::strspn(input.data(), allowed_characters) < input.length()) {
      return std::nullopt;
    }

    // Let output be the mathematical integer value that is represented by input in radix-R notation,
    // using ASCII hex digits for digits with values 0 through 15.
    return static_cast<uint16_t>(std::strtol(input.data(), nullptr, R));
  }

  /**
   * @see https://url.spec.whatwg.org/#host-parsing
   */
  std::optional<std::string_view> parse_host(std::string_view input, bool is_not_special) {
    // If input starts with U+005B ([), then:
    if (input[0] == '[') {
      // If input does not end with U+005D (]), validation error, return failure.
      if (input.back() != ']') {
        return std::nullopt;
      }

      // Return the result of IPv6 parsing input with its leading U+005B ([) and trailing U+005D (]) removed.
      return parse_ipv6(input.substr(1, input.length() - 2));
    }

    // If isNotSpecial is true, then return the result of opaque-host parsing input.
    if (is_not_special) {
      return parse_opaque_host(input);
    }

    // Let domain be the result of running UTF-8 decode without BOM on the percent-decoding of input.
    std::string_view ascii_domain{ada::unicode::utf8_decode_without_bom(input)};

    // Let asciiDomain be the result of running domain to ASCII with domain and false.
    bool ascii_domain_failed = domain_to_ascii(ascii_domain);

    // If asciiDomain is failure, validation error, return failure.
    if (ascii_domain_failed) {
      return std::nullopt;
    }

    // If asciiDomain contains a forbidden domain code point, validation error, return failure.
    // TODO: Implement this

    // If asciiDomain ends in a number, then return the result of IPv4 parsing asciiDomain.
    if (checkers::ends_in_a_number(ascii_domain)) {
      return parse_ipv4(ascii_domain);
    }

    // Return asciiDomain.
    return ascii_domain;
  }

  url parse_url(std::string_view user_input,
                std::optional<ada::url> base_url,
                ada::encoding_type encoding,
                std::optional<ada::state> state_override) {

    // Assign buffer
    std::string buffer{};

    // Assign inside brackets. Used by HOST state.
    bool inside_brackets{false};

    // Assign at sign seen.
    bool at_sign_seen{false};

    // Let state be state override if given, or scheme start state otherwise.
    ada::state state = state_override.value_or(SCHEME_START);

    // Define parsed URL
    ada::url url = ada::url();

    // Remove any leading and trailing C0 control or space from input.
    auto pointer_start = user_input.begin();
    auto pointer_end = user_input.end();

    // Let pointer be a pointer for input.
    std::string_view::iterator pointer = pointer_start;
    auto pointer_previous = pointer_start;

    // Keep running the following state machine by switching on state.
    // If after a run pointer points to the EOF code point, go to the next step.
    // Otherwise, increase pointer by 1 and continue with the state machine.
    for (; pointer <= pointer_end; pointer++) {
      if (ada::unicode::is_c0_control_or_space(*pointer) || ada::unicode::is_ascii_tab_or_newline(*pointer)) {
        continue;
      }

      pointer_previous = std::prev(pointer);

      switch (state) {
        case AUTHORITY: {
          // If c is U+0040 (@), then:
          if (*pointer == '@') {
            // If atSignSeen is true, then prepend "%40" to buffer.
            if (at_sign_seen) {
              buffer.insert(0, "%40");
            }

            // Set atSignSeen to true.
            at_sign_seen = true;

            // Find the first occurance of ':' to split authority state
            size_t password_token =  buffer.find(':');

            if (password_token == std::string::npos) {
              url.username = buffer;
            } else {
              url.username = unicode::utf8_percent_encode( buffer.substr(0, password_token), character_sets::USERINFO_PERCENT_ENCODE);
              url.password = unicode::utf8_percent_encode(buffer.substr(password_token), character_sets::USERINFO_PERCENT_ENCODE);
            }

            // Set buffer to the empty string.
            buffer.clear();
          }
          // Otherwise, if one of the following is true:
          // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
          // - url is special and c is U+005C (\)
          else if ((pointer == pointer_end || *pointer == '/' || *pointer == '?' || *pointer == '#') || (url.is_special && *pointer == '\\')) {
            // If atSignSeen is true and buffer is the empty string, validation error, return failure.
            if (at_sign_seen) {
              buffer.clear();
              url.is_valid = false;
              return url;
            }

            // Decrease pointer by the number of code points in buffer plus one,
            // set buffer to the empty string, and set state to host state.
            pointer -= buffer.length() + 1;
            buffer.clear();
            state = HOST;
          }
          // Otherwise, append c to buffer.
          else {
            buffer += *pointer;
          }

          break;
        }
        case SCHEME_START: {
          // If c is an ASCII alpha, append c, lowercased, to buffer, and set state to scheme state.
          if (std::isalpha(*pointer)) {
            buffer += static_cast<char>(tolower(*pointer));
            state = SCHEME;
          }
          // Otherwise, if state override is not given, set state to no scheme state and decrease pointer by 1.
          else if (!state_override.has_value()) {
            state = NO_SCHEME;
            pointer = pointer_previous;
          }
          // Otherwise, validation error, return failure.
          else {
            url.is_valid = false;
            return url;
          }
          break;
        }
        case SCHEME: {
          // If c is an ASCII alphanumeric, U+002B (+), U+002D (-), or U+002E (.), append c, lowercased, to buffer.
          if (std::isalnum(*pointer) || *pointer == '+' || *pointer == '-' || *pointer == '.') {
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
              if (url.scheme == "file" && url.host.empty()) {
                return url;
              }
            }

            // Set url’s scheme to buffer.
            url.scheme = buffer;
            url.is_special = ada::scheme::is_special(buffer);

            // If state override is given, then:
            if (state_override.has_value()) {
              auto urls_scheme_port = ada::scheme::SPECIAL_SCHEME.find(url.scheme);

              if (urls_scheme_port != ada::scheme::SPECIAL_SCHEME.end()) {
                // If url’s port is url’s scheme’s default port, then set url’s port to null.
                if (url.port.has_value() && *url.port == urls_scheme_port->second) {
                  url.port = std::nullopt;
                }
              }

              continue;
            }

            // Set buffer to the empty string.
            buffer.clear();

            // If url’s scheme is "file", then:
            if (url.scheme == "file") {
              // Set state to file state.
              state = FILE;
            }
            // Otherwise, if url is special, base is non-null, and base’s scheme is url’s scheme:
            else if (url.is_special && base_url.has_value() && base_url->scheme == url.scheme) {
              // Set state to special relative or authority state.
              state = SPECIAL_RELATIVE_OR_AUTHORITY;
            }
            // Otherwise, if url is special, set state to special authority slashes state.
            else if (url.is_special) {
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
            url.is_valid = false;
            return url;
          }

          break;
        }
        case NO_SCHEME: {
          // If base is null, or base has an opaque path and c is not U+0023 (#), validation error, return failure.
          if (!base_url.has_value() || (base_url->has_opaque_path() && *pointer != '#')) {
            url.is_valid = false;
            return url;
          }
          // Otherwise, if base has an opaque path and c is U+0023 (#),
          // set url’s scheme to base’s scheme, url’s path to base’s path, url’s query to base’s query,
          // url’s fragment to the empty string, and set state to fragment state.
          else if (base_url->has_opaque_path() && *pointer == '#') {
            url.is_special = ada::scheme::is_special(base_url->scheme);
            url.scheme = base_url->scheme;
            url.path = base_url->path;
            url.query = base_url->query;
            state = FRAGMENT;
          }
          // Otherwise, if base’s scheme is not "file", set state to relative state and decrease pointer by 1.
          else if (base_url->scheme != "file") {
            state = RELATIVE;
            pointer = pointer_previous;
          }
          // Otherwise, set state to file state and decrease pointer by 1.
          else {
            state = FILE;
            pointer = pointer_previous;
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
            state = RELATIVE;
            pointer = pointer_previous;
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
            pointer = pointer_previous;
          }

          break;
        }
        case RELATIVE: {
          // Set url’s scheme to base’s scheme.
          url.scheme = base_url->scheme;
          url.is_special = scheme::is_special(base_url->scheme);

          // If c is U+002F (/), then set state to relative slash state.
          if (*pointer == '/') {
            state = RELATIVE_SLASH;
          }
          // Otherwise, if url is special and c is U+005C (\), validation error, set state to relative slash state.
          else if (url.is_special && *pointer == '\\') {
            state = RELATIVE_SLASH;
          }
          // Otherwise:
          else {
            // Set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host,
            // url’s port to base’s port, url’s path to a clone of base’s path, and url’s query to base’s query.
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
            url.path = base_url->path;
            url.query = base_url->query;

            // If c is U+003F (?), then set url’s query to the empty string, and state to query state.
            if (*pointer == '?') {
              url.query = "";
              state = QUERY;
            }
            // Otherwise, if c is U+0023 (#), set url’s fragment to the empty string and state to fragment state.
            else if (*pointer == '#') {
              state = FRAGMENT;
            }
            // Otherwise, if c is not the EOF code point:
            else if (pointer != pointer_end) {
              // Set url’s query to null.
              url.query = std::nullopt;

              // Shorten url’s path.
              url.shorten_path();

              // Set state to path state and decrease pointer by 1.
              state = PATH;
              pointer = pointer_previous;
            }
          }

          break;
        }
        case RELATIVE_SLASH: {
          // If url is special and c is U+002F (/) or U+005C (\), then:
          if (url.is_special && (*pointer == '/' || *pointer =='\\')) {
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
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
            state = PATH;
            pointer = pointer_previous;
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
            pointer = pointer_previous;
          }

          state = SPECIAL_AUTHORITY_IGNORE_SLASHES;

          break;
        }
        case SPECIAL_AUTHORITY_IGNORE_SLASHES: {
          // If c is neither U+002F (/) nor U+005C (\), then set state to authority state and decrease pointer by 1.
          if (*pointer != '/' && *pointer != '\\') {
            state = AUTHORITY;
            pointer = pointer_previous;
          }

          break;
        }
        case QUERY: {
          // If encoding is not UTF-8 and one of the following is true:
          // - url is not special
          // - url’s scheme is "ws" or "wss"
          if (encoding != UTF8) {
            if (!url.is_special || url.scheme == "ws" || url.scheme == "wss") {
              // then set encoding to UTF-8.
              encoding = UTF8;
            }
          }

          // Optimization: Spec states that the buffer should be cleared, but
          // it does not make sense due to our optimization for skipping to fragment state.

          // Optimization: Spec states that we should iterate character by character.
          // But in reality we can first check the fragment character (iterator)
          // Depending on the existence we can bulk encode and assign the query
          // and later skip the pointers until the end of input or fragment iterator.

          // Let queryPercentEncodeSet be the special-query percent-encode set if url is special;
          // otherwise the query percent-encode set.
          auto query_percent_encode_set = url.is_special ?
                                ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE :
                                ada::character_sets::QUERY_PERCENT_ENCODE;

          // Let fragment iterator be the iterator for the # after the current iterator.
          auto fragment_iterator = std::find(pointer, pointer_end, '#');
          auto query = std::string(pointer, fragment_iterator);

          // Percent-encode after encoding, with encoding, buffer, and queryPercentEncodeSet,
          // and append the result to url’s query.
          url.query = ada::unicode::utf8_percent_encode(query, query_percent_encode_set);

          // If fragment iterator does not point to end of the input and state override is defined
          // set pointer to fragment pointer, state to fragment.
          if (fragment_iterator != pointer_end && !state_override.has_value()) {
            pointer = fragment_iterator;
            state = FRAGMENT;
          } else {
            return url;
          }

          break;
        }
        case HOST: {
          // If state override is given and url’s scheme is "file",
          // then decrease pointer by 1 and set state to file host state.
          if (state_override.has_value() && url.scheme == "file") {
            pointer = pointer_previous;
            state = FILE_HOST;
          }
          // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
          else if (*pointer == ':' && !inside_brackets) {
            // If buffer is the empty string, validation error, return failure.
            if (buffer.empty()) {
              url.is_valid = false;
              return url;
            }
            // If state override is given and state override is hostname state, then return.
            else if (state_override == HOST) {
              return url;
            }

            // Let host be the result of host parsing buffer with url is not special.
            std::optional<std::string_view> host = parse_host(buffer, true);

            // If host is failure, then return failure.
            if (!host.has_value()) {
              url.is_valid = false;
              return url;
            }

            // Set url’s host to host, buffer to the empty string, and state to port state.
            url.host = *host;
            buffer.clear();
            state = PORT;
          }
          // Otherwise, if one of the following is true:
          // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
          // - url is special and c is U+005C (\)
          else if (pointer == pointer_end || *pointer == '/' || *pointer == '?' || *pointer == '#' || (url.is_special && *pointer == '\\')) {
            // then decrease pointer by 1, and then:
            pointer = pointer_previous;

            // If url is special and buffer is the empty string, validation error, return failure.
            if (url.is_special && buffer.empty()) {
              url.is_valid = false;
              return url;
            }
            // Otherwise, if state override is given, buffer is the empty string,
            // and either url includes credentials or url’s port is non-null, return.
            else if (state_override.has_value() && buffer.empty() && (url.includes_credentials() || url.port.has_value())) {
              return url;
            }

            // Let host be the result of host parsing buffer with url is not special.
            std::optional<std::string_view> host = parse_host(buffer, true);

            // If host is failure, then return failure.
            if (!host.has_value()) {
              url.is_valid = false;
              return url;
            }

            // Set url’s host to host, buffer to the empty string, and state to path start state.
            url.host = *host;
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
            // Optimization: Spec states that we should iterate character by character, instead of bulk operation.
            // UTF-8 percent-encode c using the fragment percent-encode set and append the result to url’s fragment.
            url.fragment = unicode::utf8_percent_encode(
                                  std::string(pointer, pointer_end),
                                  ada::character_sets::FRAGMENT_PERCENT_ENCODE);
            return url;
          }

          break;
        }
        case OPAQUE_PATH: {
          // If c is U+003F (?), then set url’s query to the empty string and state to query state.
          if (*pointer == '?') {
            state = QUERY;
          }
          // Otherwise, if c is U+0023 (#), then set url’s fragment to the empty string and state to fragment state.
          else if (*pointer == '#') {
            state = FRAGMENT;
          }
          // Otherwise:
          else {
            // If c is not the EOF code point, UTF-8 percent-encode c using the C0 control percent-encode set
            // and append the result to url’s path.
            if (pointer != pointer_end) {
              // TODO: No need to iterate and push_back character by character. We can do it in bulk.
              std::string encoded = unicode::utf8_percent_encode(pointer, character_sets::C0_CONTROL_PERCENT_ENCODE);
              url.path.list_value.push_back(encoded);
            }
          }

          break;
        }
        case PORT: {
          // If c is an ASCII digit, append c to buffer.
          if (std::isdigit(*pointer)) {
            buffer += *pointer;
          }
          // Otherwise, if one of the following is true:
          // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
          // - url is special and c is U+005C (\)
          // - state override is given
          else if (pointer == pointer_end || *pointer == '/' || *pointer == '?' || *pointer == '#' ||
                                (url.is_special && *pointer == '\\') ||
                                state_override.has_value()) {
            // If buffer is not the empty string, then:
            if (!buffer.empty()) {
              // Let port be the mathematical integer value that is represented by buffer in radix-10
              // using ASCII digits for digits with values 0 through 9.
              auto port = static_cast<uint16_t>(std::strtoul(buffer.c_str(), nullptr, 10));

              // If port is greater than 216 − 1, validation error, return failure.
              if (port > (std::pow(2, 16) - 1)) {
                url.is_valid = false;
                return url;
              }

              // Set url’s port to null, if port is url’s scheme’s default port; otherwise to port.
              if (port == url.scheme_default_port()) {
                url.port = std::nullopt;
              } else {
                url.port = port;
              }

              // Set buffer to the empty string.
              buffer.clear();
            }

            // If state override is given, then return.
            if (state_override.has_value()) {
              return url;
            }

            // Set state to path start state and decrease pointer by 1.
            state = PATH_START;
            pointer = pointer_previous;
          }
          // Otherwise, validation error, return failure.
          else {
            url.is_valid = false;
            return url;
          }

          break;
        }
        case PATH_START: {
          // If url is special, then:
          if (url.is_special) {
            // Set state to path state.
            state = PATH;

            // If c is neither U+002F (/) nor U+005C (\), then decrease pointer by 1.
            if (*pointer != '/' && *pointer != '\\') {
              pointer = pointer_previous;
            }
          }
          // Otherwise, if state override is not given and c is U+003F (?),
          // set url’s query to the empty string and state to query state.
          else if (!state_override.has_value() && *pointer == '?') {
            state = QUERY;
          }
          // Otherwise, if state override is not given and c is U+0023 (#),
          // set url’s fragment to the empty string and state to fragment state.
          else if (!state_override.has_value() && *pointer == '#') {
            state = FRAGMENT;
          }
          // Otherwise, if c is not the EOF code point:
          else if (pointer != pointer_end) {
            // Set state to path state.
            state = PATH;

            // If c is not U+002F (/), then decrease pointer by 1.
            if (*pointer != '/') {
              pointer = pointer_previous;
            }
          }
          // Otherwise, if state override is given and url’s host is null, append the empty string to url’s path.
          else if (state_override.has_value() && url.host.empty()) {
            // To append to a list that is not an ordered set is to add the given item to the end of the list.
            url.path.list_value.emplace_back("");
          }

          break;
        }
        case PATH: {
          // If one of the following is true:
          // - c is the EOF code point or U+002F (/)
          // - url is special and c is U+005C (\)
          // - state override is not given and c is U+003F (?) or U+0023 (#)
          if (pointer == pointer_end || *pointer == '/' || (url.is_special && *pointer == '\\') || (!state_override.has_value() && (*pointer == '?' || *pointer == '#'))) {
            // If buffer is a double-dot path segment, then:
            if (unicode::is_double_dot_path_segment(buffer)) {
              // Shorten url’s path.
              url.shorten_path();

              // If neither c is U+002F (/), nor url is special and c is U+005C (\),
              // append the empty string to url’s path.
              if (*pointer != '/' && !(url.is_special && *pointer == '\\')) {
                url.path.list_value.emplace_back("");
              }
            }
            // Otherwise, if buffer is a single-dot path segment and if neither c is U+002F (/),
            // nor url is special and c is U+005C (\), append the empty string to url’s path.
            else if (unicode::is_single_dot_path_segment(buffer) && *pointer != '/' && !(url.is_special && *pointer == '\\')) {
              url.path.list_value.emplace_back("");
            }
            // Otherwise, if buffer is not a single-dot path segment, then:
            else if (!unicode::is_single_dot_path_segment(buffer)) {
              // If url’s scheme is "file", url’s path is empty, and buffer is a Windows drive letter,
              // then replace the second code point in buffer with U+003A (:).
              if (url.scheme == "file" && url.path.list_value.empty() && checkers::is_windows_drive_letter(buffer)){
                buffer[1] = ':';
              }

              // Append buffer to url’s path.
              url.path.list_value.push_back(buffer);
            }

            // Set buffer to the empty string.
            buffer.clear();

            // If c is U+003F (?), then set url’s query to the empty string and state to query state.
            if (*pointer == '?') {
              state = QUERY;
            }
            // If c is U+0023 (#), then set url’s fragment to the empty string and state to fragment state.
            else if (*pointer == '#') {
              state = FRAGMENT;
            }
          }
          // Otherwise, run these steps:
          else {
            // UTF-8 percent-encode c using the path percent-encode set and append the result to buffer.
            buffer += unicode::utf8_percent_encode(pointer, character_sets::PATH_PERCENT_ENCODE);
          }
          break;
        }
        case FILE_SLASH: {
          // If c is U+002F (/) or U+005C (\), then:
          if (*pointer == '/' || *pointer == '\\') {
            // Set state to file host state.
            state = FILE_HOST;
          }
          // Otherwise:
          else {
            // If base is non-null and base’s scheme is "file", then:
            if (base_url->scheme == "file") {
              // Set url’s host to base’s host.
              url.host = base_url->host;

              // If the code point substring from pointer to the end of input does not start with
              // a Windows drive letter and base’s path[0] is a normalized Windows drive letter,
              // then append base’s path[0] to url’s path.
              if (std::distance(pointer, pointer_end) < 1 && !base_url->path.list_value.empty()) {
                auto starts_with_windows_drive_letter = checkers::is_windows_drive_letter(pointer + pointer[0]);
                auto first_base_url_path = base_url->path.list_value[0];

                if (!starts_with_windows_drive_letter && checkers::is_normalized_windows_drive_letter(first_base_url_path)) {
                  url.path.list_value.push_back(first_base_url_path);
                }
              }
            }

            // Set state to path state, and decrease pointer by 1.
            state = PATH;
            pointer = pointer_previous;
          }

          break;
        }
        case FILE_HOST: {
          // If c is the EOF code point, U+002F (/), U+005C (\), U+003F (?), or U+0023 (#),
          // then decrease pointer by 1 and then:
          if (pointer == pointer_end || *pointer == '/' || *pointer == '\\' || *pointer == '?' || *pointer == '#') {
            pointer = pointer_previous;

            // If state override is not given and buffer is a Windows drive letter, validation error,
            // set state to path state.
            if (!state_override.has_value() && checkers::is_windows_drive_letter(buffer)) {
              state = PATH;
            }
            // Otherwise, if buffer is the empty string, then:
            else if (buffer.empty()) {
              // Set url’s host to the empty string.
              url.host = "";

              // If state override is given, then return.
              if (state_override.has_value()) {
                return url;
              }

              // Set state to path start state.
              state = PATH_START;
            }
            // Otherwise, run these steps:
            else {
              // Let host be the result of host parsing buffer with url is not special.
              std::optional<std::string_view> host = parse_host(buffer, true);

              // If host is failure, then return failure.
              if (!host.has_value()) {
                url.is_valid = false;
                return url;
              }

              // If host is "localhost", then set host to the empty string.
              if (*host == "localhost") {
                host = "";
              }

              // Set url’s host to host.
              url.host = *host;

              // If state override is given, then return.
              if (state_override.has_value()) {
                return url;
              }

              // Set buffer to the empty string and state to path start state.
              buffer.clear();
              state = PATH_START;
            }
          }
          // Otherwise, append c to buffer.
          else {
            buffer += *pointer;
          }

          break;
        }
        case FILE: {
          // Set url’s scheme to "file".
          url.scheme = "file";
          url.is_special = true;

          // Set url’s host to the empty string.
          url.host.clear();

          // If c is U+002F (/) or U+005C (\), then:
          if (*pointer == '/' || *pointer == '\\') {
            // Set state to file slash state.
            state = FILE_SLASH;
          }
          // Otherwise, if base is non-null and base’s scheme is "file":
          else if (base_url.has_value() && base_url->scheme == "file") {
            // Set url’s host to base’s host, url’s path to a clone of base’s path, and url’s query to base’s query.
            url.host = base_url->host;
            url.path = base_url->path;
            url.query = base_url->query;

            // If c is U+003F (?), then set url’s query to the empty string and state to query state.
            if (*pointer == '?') {
              state = QUERY;
            }
            // Otherwise, if c is U+0023 (#), set url’s fragment to the empty string and state to fragment state.
            else if (*pointer == '#') {
              url.fragment = "";
              state = FRAGMENT;
            }
            // Otherwise, if c is not the EOF code point:
            else if (pointer != pointer_end) {
              // Set url’s query to null.
              url.query = std::nullopt;

              // If the code point substring from pointer to the end of input does not start with a
              // Windows drive letter, then shorten url’s path.
              if (std::distance(pointer, pointer_end) && !checkers::is_windows_drive_letter(pointer + pointer[0])) {
                url.shorten_path();
              }
              // Otherwise:
              else {
                // Set url’s path to an empty list.
                url.path.list_value.clear();
              }

              // Set state to path state and decrease pointer by 1.
              state = PATH;
              pointer = pointer_previous;
            }
          }
          // Otherwise, set state to path state, and decrease pointer by 1.
          else {
            state = PATH;
            pointer = pointer_previous;
          }

          break;
        }
        default:
          printf("not implemented");
      }
    }

    return url;
  }

} // namespace ada::parser
