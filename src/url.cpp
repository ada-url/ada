#include "ada.h"
#include "ada/scheme.h"

#include <numeric>
#include <algorithm>
#include <string>

namespace ada {
  ada_really_inline bool url::parse_path(std::string_view input) {
    std::string tmp_buffer;
    std::string_view internal_input;
    if(std::any_of(input.begin(), input.end(), ada::unicode::is_ascii_tab_or_newline)) {
      tmp_buffer = input;
      // Optimization opportunity: Instead of copying and then pruning, we could just directly
      // build the string from user_input.
      helpers::remove_ascii_tab_or_newline(tmp_buffer);
      internal_input = tmp_buffer;
    } else {
      internal_input = input;
    }

    // If url is special, then:
    if (is_special()) {
      if(internal_input.empty()) {
        path = "/";
      } else if((internal_input[0] == '/') ||(internal_input[0] == '\\')){
        parse_prepared_path(internal_input.substr(1));
      } else {
        parse_prepared_path(internal_input);
      }
    } else if (!internal_input.empty()) {
      if(internal_input[0] == '/') {
        parse_prepared_path(internal_input.substr(1));
      } else {
        parse_prepared_path(internal_input);
      }
    } else {
      if(!host.has_value()) {
        path = "/";
      }
    }
    return true;
  }

  ada_really_inline bool url::parse_prepared_path(std::string_view input) {
    path="";
    bool needs_percent_encoding = input.end() != std::find_if(input.begin(), input.end(),
    [](uint8_t c) {
      // All the characters values needing percent encoding are within these ranges:
      return c <= 35 || c > 122 || c == 96 || (c>59 && c<=63) ; } );
    std::string path_buffer_tmp;
    do {
      size_t location = is_special() ? input.find_first_of("/\\") : input.find('/');
      std::string_view path_view = input;
      if(location != std::string_view::npos) {
        path_view.remove_suffix(path_view.size() - location);
        input.remove_prefix(location + 1);
      } else {
        input.remove_prefix(input.size()); // make it empty!
      }
      std::string_view path_buffer = path_view;
      if(needs_percent_encoding) {
        path_buffer_tmp = ada::unicode::percent_encode(path_view, character_sets::PATH_PERCENT_ENCODE);
        path_buffer = path_buffer_tmp;
      }
      if (unicode::is_double_dot_path_segment(path_buffer)) {
        helpers::shorten_path(*this);
        if (location == std::string_view::npos) {
          path += '/';
        }
      }
      else if (unicode::is_single_dot_path_segment(path_buffer) && (location == std::string_view::npos)) {
        path += '/';
      }
      // Otherwise, if path_buffer is not a single-dot path segment, then:
      else if (!unicode::is_single_dot_path_segment(path_buffer)) {
        // If url’s scheme is "file", url’s path is empty, and path_buffer is a Windows drive letter,
        // then replace the second code point in path_buffer with U+003A (:).
        if (get_scheme_type() == ada::scheme::type::FILE && path.empty() && checkers::is_windows_drive_letter(path_buffer)){
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
      if(location == std::string_view::npos) { break; }

    } while(true);
    return true;
  }

  /**
   * Return true on success.
   * @see https://url.spec.whatwg.org/#concept-opaque-host-parser
   */
  bool url::parse_opaque_host(std::string_view input) noexcept {
    if (std::any_of(input.begin(), input.end(), ada::unicode::is_forbidden_host_code_point)) {
      return is_valid = false;
    }

    // Return the result of running UTF-8 percent-encode on input using the C0 control percent-encode set.
    host = ada::unicode::percent_encode(input, ada::character_sets::C0_CONTROL_PERCENT_ENCODE);
    return true;
  }

  /**
   * Return true on success.
   * @see https://url.spec.whatwg.org/#concept-ipv4-parser
   */
  bool url::parse_ipv4(std::string_view input) {
    if(input[input.size()-1]=='.') {
      input.remove_suffix(1);
    }
    size_t digit_count{0};
    uint64_t ipv4{0};
    // we could unroll for better performance?
    for(;(digit_count < 4) && !(input.empty()); digit_count++) {
      uint32_t result{}; // If any number exceeds 32 bits, we have an error.
      bool is_hex = checkers::has_hex_prefix(input);
      if(is_hex && ((input.length() == 2)|| ((input.length() > 2) && (input[2]=='.')))) {
        // special case
        result = 0;
        input.remove_prefix(2);
      } else {
        std::from_chars_result r;
        if(is_hex) {
          r = std::from_chars(input.data() + 2, input.data() + input.size(), result, 16);
        } else if ((input.length() >= 2) && input[0] == '0' && checkers::is_digit(input[1])) {
          r = std::from_chars(input.data() + 1, input.data() + input.size(), result, 8);
        } else {
          r = std::from_chars(input.data(), input.data() + input.size(), result, 10);
        }
        if (r.ec != std::errc()) { return is_valid = false; }
        input.remove_prefix(r.ptr-input.data());
      }
      if(input.empty()) {
        // We have the last value.
        // At this stage, ipv4 contains digit_count*8 bits.
        // So we have 32-digit_count*8 bits left.
        if(result > (uint64_t(1)<<(32-digit_count*8))) { return is_valid = false; }
        ipv4 <<=(32-digit_count*8);
        ipv4 |= result;
        goto final;
      } else {
        // There is more, so that the value must no be larger than 255
        // and we must have a '.'.
        if ((result>255) || (input[0]!='.')) { return is_valid = false; }
        ipv4 <<=8;
        ipv4 |= result;
        input.remove_prefix(1); // remove '.'
      }
    }
    if((digit_count != 4) || (!input.empty())) {return is_valid = false; }
    final:
    // We could also check result.ptr to see where the parsing ended.
    host = ada::serializers::ipv4(ipv4);
    return true;
  }

  /**
   * Return true on success.
   * @see https://url.spec.whatwg.org/#concept-ipv6-parser
   */
  bool url::parse_ipv6(std::string_view input) {

    if(input.empty()) { return is_valid = false; }
    // Let address be a new IPv6 address whose IPv6 pieces are all 0.
    std::array<uint16_t, 8> address{};

    // Let pieceIndex be 0.
    int piece_index = 0;

    // Let compress be null.
    std::optional<int> compress{};

    // Let pointer be a pointer for input.
    std::string_view::iterator pointer = input.begin();

    // If c is U+003A (:), then:
    if (input[0] == ':') {
      // If remaining does not start with U+003A (:), validation error, return failure.
      if(input.size() == 1 && input[2] != ':') {
        return is_valid = false;
      }

      // Increase pointer by 2.
      pointer += 2;

      // Increase pieceIndex by 1 and then set compress to pieceIndex.
      compress = ++piece_index;
    }

    // While c is not the EOF code point:
    while (pointer != input.end()) {
      // If pieceIndex is 8, validation error, return failure.
      if (piece_index == 8) {
        return is_valid = false;
      }

      // If c is U+003A (:), then:
      if (*pointer == ':') {
        // If compress is non-null, validation error, return failure.
        if (compress.has_value()) {
          return is_valid = false;
        }

        // Increase pointer and pieceIndex by 1, set compress to pieceIndex, and then continue.
        pointer++;
        compress = ++piece_index;
        continue;
      }

      // Let value and length be 0.
      uint16_t value = 0, length = 0;

      // While length is less than 4 and c is an ASCII hex digit,
      // set value to value × 0x10 + c interpreted as hexadecimal number, and increase pointer and length by 1.
      while (length < 4 && unicode::is_ascii_hex_digit(*pointer)) {
        // https://stackoverflow.com/questions/39060852/why-does-the-addition-of-two-shorts-return-an-int
        value = uint16_t(value * 0x10 + unicode::convert_hex_to_binary(*pointer));
        pointer++;
        length++;
      }

      // If c is U+002E (.), then:
      if (*pointer == '.') {
        // If length is 0, validation error, return failure.
        if (length == 0) {
          return is_valid = false;
        }

        // Decrease pointer by length.
        pointer -= length;

        // If pieceIndex is greater than 6, validation error, return failure.
        if (piece_index > 6) {
          return is_valid = false;
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
              return is_valid = false;
            }
          }

          // If c is not an ASCII digit, validation error, return failure.
          if (!checkers::is_digit(*pointer)) {
            return is_valid = false;
          }

          // While c is an ASCII digit:
          while (checkers::is_digit(*pointer)) {
            // Let number be c interpreted as decimal number.
            int number = *pointer - '0';

            // If ipv4Piece is null, then set ipv4Piece to number.
            if (!ipv4_piece.has_value()) {
              ipv4_piece = number;
            }
            // Otherwise, if ipv4Piece is 0, validation error, return failure.
            else if (ipv4_piece == 0) {
              return is_valid = false;
            }
            // Otherwise, set ipv4Piece to ipv4Piece × 10 + number.
            else {
              ipv4_piece = *ipv4_piece * 10 + number;
            }

            // If ipv4Piece is greater than 255, validation error, return failure.
            if (ipv4_piece > 255) {
              return is_valid = false;
            }

            // Increase pointer by 1.
            pointer++;
          }

          // Set address[pieceIndex] to address[pieceIndex] × 0x100 + ipv4Piece.
          // https://stackoverflow.com/questions/39060852/why-does-the-addition-of-two-shorts-return-an-int
          address[piece_index] = uint16_t(address[piece_index] * 0x100 + *ipv4_piece);

          // Increase numbersSeen by 1.
          numbers_seen++;

          // If numbersSeen is 2 or 4, then increase pieceIndex by 1.
          if (numbers_seen == 2 || numbers_seen == 4) {
            piece_index++;
          }
        }

        // If numbersSeen is not 4, validation error, return failure.
        if (numbers_seen != 4) {
          return is_valid = false;
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
          return is_valid = false;
        }
      }
      // Otherwise, if c is not the EOF code point, validation error, return failure.
      else if (pointer != input.end()) {
        return is_valid = false;
      }

      // Set address[pieceIndex] to value.
      address[piece_index] = value;

      // Increase pieceIndex by 1.
      piece_index++;
    }

    // If compress is non-null, then:
    if (compress.has_value()) {
      // Let swaps be pieceIndex − compress.
      int swaps = piece_index - *compress;

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
      return is_valid = false;
    }

    host = ada::serializers::ipv6(address);
    return true;
  }

  /**
   * Return true on success.
   * @see https://url.spec.whatwg.org/#host-parsing
   */
  ada_really_inline bool url::parse_host(const std::string_view input) {
    //
    // Note: this function assumes that parse_host is not empty. Make sure we can
    // guarantee that.
    //
    if(input.empty()) { return is_valid = false; }
    // If input starts with U+005B ([), then:
    if (input[0] == '[') {
      // If input does not end with U+005D (]), validation error, return failure.
      if (input.back() != ']') {
        return is_valid = false;
      }

      // Return the result of IPv6 parsing input with its leading U+005B ([) and trailing U+005D (]) removed.
      return parse_ipv6(std::string_view(input.begin() + 1, input.end() - input.begin() - 2));
    }

    // If isNotSpecial is true, then return the result of opaque-host parsing input.
    if (!is_special()) {
      return parse_opaque_host(input);
    }
    static_assert(ada::unicode::is_forbidden_domain_code_point('%'));

    // Let domain be the result of running UTF-8 decode without BOM on the percent-decoding of input.
    // Let asciiDomain be the result of running domain to ASCII with domain and false.
    // The most common case is an ASCII input, in which case we do not need to call the expensive 'to_ascii'
    // if a few conditions are met: no '%' and no 'xn-' subsequence.
    //size_t first_percent = input.find('%');
    if (ada::unicode::is_forbidden_domain_code_point('%')) {
      std::string buffer;
      bool is_forbidden{false};
      uint8_t ascii_runner{0};

      buffer.reserve(input.size());
      std::transform(input.begin(), input.end(), std::back_inserter(buffer), [&is_forbidden, &ascii_runner](char c) -> char {
        is_forbidden |= ada::unicode::is_forbidden_domain_code_point(c);
        ascii_runner |= c;
        return (uint8_t((c|0x20) - 0x61) <= 25 ? (c|0x20) : c);}
      );
      if (ascii_runner < 128 && !is_forbidden && buffer.find("xn-") == std::string_view::npos) {
        // fast path
        host = std::move(buffer);
        if (checkers::is_ipv4(host.value())) {
          return parse_ipv4(host.value());
        }
        return true;
      }
    }

    is_valid = ada::unicode::to_ascii(host, input, false,  input.find('%'));
    if (!is_valid) { return is_valid = false; }

    // If asciiDomain ends in a number, then return the result of IPv4 parsing asciiDomain.
    if(checkers::is_ipv4(host.value())) {
      return parse_ipv4(host.value());
    }
    return true;
  }

  ada_really_inline bool url::parse_scheme(const std::string_view input, const bool has_state_override) {
    std::string _buffer;
    std::transform(input.begin(), input.end(), std::back_inserter(_buffer),
        [](char c) -> char { return (uint8_t((c|0x20) - 0x61) <= 25 ? (c|0x20) : c);});

    if (has_state_override) {
      // If url’s scheme is a special scheme and buffer is not a special scheme, then return.
      // If url’s scheme is not a special scheme and buffer is a special scheme, then return.
      if (is_special() != ada::scheme::is_special(_buffer)) {
        return true;
      }

      // If url includes credentials or has a non-null port, and buffer is "file", then return.
      if ((includes_credentials() || port.has_value()) && _buffer == "file") {
        return true;
      }

      // If url’s scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (get_scheme_type() == ada::scheme::type::FILE && host.has_value() && host.value().empty()) {
        return true;
      }
    }

    set_scheme(std::move(_buffer));

    if (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url’s port is url’s scheme’s default port, then set url’s port to null.
        if (port.has_value() && *port == urls_scheme_port) {
          port = std::nullopt;
        }
      }
    }

    return true;
  }

  std::string url::to_string() {
    if (!is_valid) {
      return "null";
    }
    // TODO: make sure that this is valid JSON by encoding the strings.
    // TODO: pre-allocate memory and write into it to avoid allocations
    // and copies during concatenation.
    return "{\"scheme\":\"" + scheme + "\"" + ","
         + "\"username\":\"" + username + "\"" + "," + "\"password\":\"" +
         password + "\"" + "," +
         (host.has_value() ? "\"host\":\"" + host.value() + "\"" + "," : "") +
         (port.has_value() ? "\"port\":" + std::to_string(port.value()) + "" + ","
                         : "") +
         "\"path\":\"" + path + "\"" +
         (query.has_value() ? ",\"query\":\"" + query.value() + "\"" + ","
                          : "") +
         (fragment.has_value()
              ? ",\"fragment\":\"" + fragment.value() + "\"" + ","
              : "") + "}";
  }

} // namespace ada
