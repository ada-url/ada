#include "ada/scheme-inl.h"
#include "ada/log.h"
#include "ada/unicode-inl.h"

#include <numeric>
#include <algorithm>
#include <string>
#include <string_view>

namespace ada {

bool url::parse_opaque_host(std::string_view input) {
  ada_log("parse_opaque_host ", input, " [", input.size(), " bytes]");
  if (std::ranges::any_of(input.begin(), input.end(),
                          ada::unicode::is_forbidden_host_code_point)) {
    return is_valid = false;
  }

  // Return the result of running UTF-8 percent-encode on input using the C0
  // control percent-encode set.
  host = ada::unicode::percent_encode(
      input, ada::character_sets::C0_CONTROL_PERCENT_ENCODE);
  return true;
}

bool url::parse_ipv4(std::string_view input) {
  ada_log("parse_ipv4 ", input, " [", input.size(), " bytes]");
  if (input.back() == '.') {
    input.remove_suffix(1);
  }
  size_t digit_count{0};
  int pure_decimal_count = 0;  // entries that are decimal
  std::string_view original_input =
      input;  // we might use this if pure_decimal_count == 4.
  uint64_t ipv4{0};
  // we could unroll for better performance?
  for (; (digit_count < 4) && !(input.empty()); digit_count++) {
    uint32_t
        segment_result{};  // If any number exceeds 32 bits, we have an error.
    bool is_hex = checkers::has_hex_prefix(input);
    if (is_hex && ((input.length() == 2) ||
                   ((input.length() > 2) && (input[2] == '.')))) {
      // special case
      segment_result = 0;
      input.remove_prefix(2);
    } else {
      std::from_chars_result r{};
      if (is_hex) {
        r = std::from_chars(input.data() + 2, input.data() + input.size(),
                            segment_result, 16);
      } else if ((input.length() >= 2) && input[0] == '0' &&
                 checkers::is_digit(input[1])) {
        r = std::from_chars(input.data() + 1, input.data() + input.size(),
                            segment_result, 8);
      } else {
        pure_decimal_count++;
        r = std::from_chars(input.data(), input.data() + input.size(),
                            segment_result, 10);
      }
      if (r.ec != std::errc()) {
        return is_valid = false;
      }
      input.remove_prefix(r.ptr - input.data());
    }
    if (input.empty()) {
      // We have the last value.
      // At this stage, ipv4 contains digit_count*8 bits.
      // So we have 32-digit_count*8 bits left.
      if (segment_result >= (uint64_t(1) << (32 - digit_count * 8))) {
        return is_valid = false;
      }
      ipv4 <<= (32 - digit_count * 8);
      ipv4 |= segment_result;
      goto final;
    } else {
      // There is more, so that the value must no be larger than 255
      // and we must have a '.'.
      if ((segment_result > 255) || (input[0] != '.')) {
        return is_valid = false;
      }
      ipv4 <<= 8;
      ipv4 |= segment_result;
      input.remove_prefix(1);  // remove '.'
    }
  }
  if ((digit_count != 4) || (!input.empty())) {
    return is_valid = false;
  }
final:
  // We could also check r.ptr to see where the parsing ended.
  if (pure_decimal_count == 4) {
    host = original_input;  // The original input was already all decimal and we
                            // validated it.
  } else {
    host = ada::serializers::ipv4(ipv4);  // We have to reserialize the address.
  }
  host_type = IPV4;
  return true;
}

bool url::parse_ipv6(std::string_view input) {
  ada_log("parse_ipv6 ", input, " [", input.size(), " bytes]");

  if (input.empty()) {
    return is_valid = false;
  }
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
    // If remaining does not start with U+003A (:), validation error, return
    // failure.
    if (input.size() == 1 || input[1] != ':') {
      ada_log("parse_ipv6 starts with : but the rest does not start with :");
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
      ada_log("parse_ipv6 piece_index == 8");
      return is_valid = false;
    }

    // If c is U+003A (:), then:
    if (*pointer == ':') {
      // If compress is non-null, validation error, return failure.
      if (compress.has_value()) {
        ada_log("parse_ipv6 compress is non-null");
        return is_valid = false;
      }

      // Increase pointer and pieceIndex by 1, set compress to pieceIndex, and
      // then continue.
      pointer++;
      compress = ++piece_index;
      continue;
    }

    // Let value and length be 0.
    uint16_t value = 0, length = 0;

    // While length is less than 4 and c is an ASCII hex digit,
    // set value to value times 0x10 + c interpreted as hexadecimal number, and
    // increase pointer and length by 1.
    while (length < 4 && pointer != input.end() &&
           unicode::is_ascii_hex_digit(*pointer)) {
      // https://stackoverflow.com/questions/39060852/why-does-the-addition-of-two-shorts-return-an-int
      value = uint16_t(value * 0x10 + unicode::convert_hex_to_binary(*pointer));
      pointer++;
      length++;
    }

    // If c is U+002E (.), then:
    if (pointer != input.end() && *pointer == '.') {
      // If length is 0, validation error, return failure.
      if (length == 0) {
        ada_log("parse_ipv6 length is 0");
        return is_valid = false;
      }

      // Decrease pointer by length.
      pointer -= length;

      // If pieceIndex is greater than 6, validation error, return failure.
      if (piece_index > 6) {
        ada_log("parse_ipv6 piece_index > 6");
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
          // If c is a U+002E (.) and numbersSeen is less than 4, then increase
          // pointer by 1.
          if (*pointer == '.' && numbers_seen < 4) {
            pointer++;
          }
          // Otherwise, validation error, return failure.
          else {
            ada_log("parse_ipv6 Otherwise, validation error, return failure");
            return is_valid = false;
          }
        }

        // If c is not an ASCII digit, validation error, return failure.
        if (pointer == input.end() || !checkers::is_digit(*pointer)) {
          ada_log(
              "parse_ipv6 If c is not an ASCII digit, validation error, return "
              "failure");
          return is_valid = false;
        }

        // While c is an ASCII digit:
        while (pointer != input.end() && checkers::is_digit(*pointer)) {
          // Let number be c interpreted as decimal number.
          int number = *pointer - '0';

          // If ipv4Piece is null, then set ipv4Piece to number.
          if (!ipv4_piece.has_value()) {
            ipv4_piece = number;
          }
          // Otherwise, if ipv4Piece is 0, validation error, return failure.
          else if (ipv4_piece == 0) {
            ada_log("parse_ipv6 if ipv4Piece is 0, validation error");
            return is_valid = false;
          }
          // Otherwise, set ipv4Piece to ipv4Piece times 10 + number.
          else {
            ipv4_piece = *ipv4_piece * 10 + number;
          }

          // If ipv4Piece is greater than 255, validation error, return failure.
          if (ipv4_piece > 255) {
            ada_log("parse_ipv6 ipv4_piece > 255");
            return is_valid = false;
          }

          // Increase pointer by 1.
          pointer++;
        }

        // Set address[pieceIndex] to address[pieceIndex] times 0x100 +
        // ipv4Piece.
        // https://stackoverflow.com/questions/39060852/why-does-the-addition-of-two-shorts-return-an-int
        address[piece_index] =
            uint16_t(address[piece_index] * 0x100 + *ipv4_piece);

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
    else if ((pointer != input.end()) && (*pointer == ':')) {
      // Increase pointer by 1.
      pointer++;

      // If c is the EOF code point, validation error, return failure.
      if (pointer == input.end()) {
        ada_log(
            "parse_ipv6 If c is the EOF code point, validation error, return "
            "failure");
        return is_valid = false;
      }
    }
    // Otherwise, if c is not the EOF code point, validation error, return
    // failure.
    else if (pointer != input.end()) {
      ada_log(
          "parse_ipv6 Otherwise, if c is not the EOF code point, validation "
          "error, return failure");
      return is_valid = false;
    }

    // Set address[pieceIndex] to value.
    address[piece_index] = value;

    // Increase pieceIndex by 1.
    piece_index++;
  }

  // If compress is non-null, then:
  if (compress.has_value()) {
    // Let swaps be pieceIndex - compress.
    int swaps = piece_index - *compress;

    // Set pieceIndex to 7.
    piece_index = 7;

    // While pieceIndex is not 0 and swaps is greater than 0,
    // swap address[pieceIndex] with address[compress + swaps - 1], and then
    // decrease both pieceIndex and swaps by 1.
    while (piece_index != 0 && swaps > 0) {
      std::swap(address[piece_index], address[*compress + swaps - 1]);
      piece_index--;
      swaps--;
    }
  }
  // Otherwise, if compress is null and pieceIndex is not 8, validation error,
  // return failure.
  else if (piece_index != 8) {
    ada_log(
        "parse_ipv6 if compress is null and pieceIndex is not 8, validation "
        "error, return failure");
    return is_valid = false;
  }
  host = ada::serializers::ipv6(address);
  ada_log("parse_ipv6 ", *host);
  host_type = IPV6;
  return true;
}

template <bool has_state_override>
ada_really_inline bool url::parse_scheme(const std::string_view input) {
  auto parsed_type = ada::scheme::get_scheme_type(input);
  bool is_input_special = (parsed_type != ada::scheme::NOT_SPECIAL);
  /**
   * In the common case, we will immediately recognize a special scheme (e.g.,
   *http, https), in which case, we can go really fast.
   **/
  if (is_input_special) {  // fast path!!!
    if constexpr (has_state_override) {
      // If url's scheme is not a special scheme and buffer is a special scheme,
      // then return.
      if (is_special() != is_input_special) {
        return false;
      }

      // If url includes credentials or has a non-null port, and buffer is
      // "file", then return.
      if ((has_credentials() || port.has_value()) &&
          parsed_type == ada::scheme::type::FILE) {
        return false;
      }

      // If url's scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE && host.has_value() &&
          host.value().empty()) {
        return false;
      }
    }

    type = parsed_type;

    if constexpr (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url's port is url's scheme's default port, then set url's port to
        // null.
        if (port.has_value() && *port == urls_scheme_port) {
          port = std::nullopt;
        }
      }
    }
  } else {  // slow path
    std::string _buffer(input);
    // Next function is only valid if the input is ASCII and returns false
    // otherwise, but it seems that we always have ascii content so we do not
    // need to check the return value.
    // bool is_ascii =
    unicode::to_lower_ascii(_buffer.data(), _buffer.size());

    if constexpr (has_state_override) {
      // If url's scheme is a special scheme and buffer is not a special scheme,
      // then return. If url's scheme is not a special scheme and buffer is a
      // special scheme, then return.
      if (is_special() != ada::scheme::is_special(_buffer)) {
        return true;
      }

      // If url includes credentials or has a non-null port, and buffer is
      // "file", then return.
      if ((has_credentials() || port.has_value()) && _buffer == "file") {
        return true;
      }

      // If url's scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE && host.has_value() &&
          host.value().empty()) {
        return true;
      }
    }

    set_scheme(std::move(_buffer));

    if constexpr (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url's port is url's scheme's default port, then set url's port to
        // null.
        if (port.has_value() && *port == urls_scheme_port) {
          port = std::nullopt;
        }
      }
    }
  }

  return true;
}

ada_really_inline bool url::parse_host(std::string_view input) {
  ada_log("parse_host ", input, " [", input.size(), " bytes]");
  if (input.empty()) {
    return is_valid = false;
  }  // technically unnecessary.
  // If input starts with U+005B ([), then:
  if (input[0] == '[') {
    // If input does not end with U+005D (]), validation error, return failure.
    if (input.back() != ']') {
      return is_valid = false;
    }
    ada_log("parse_host ipv6");

    // Return the result of IPv6 parsing input with its leading U+005B ([) and
    // trailing U+005D (]) removed.
    input.remove_prefix(1);
    input.remove_suffix(1);
    return parse_ipv6(input);
  }

  // If isNotSpecial is true, then return the result of opaque-host parsing
  // input.
  if (!is_special()) {
    return parse_opaque_host(input);
  }
  // Let domain be the result of running UTF-8 decode without BOM on the
  // percent-decoding of input. Let asciiDomain be the result of running domain
  // to ASCII with domain and false. The most common case is an ASCII input, in
  // which case we do not need to call the expensive 'to_ascii' if a few
  // conditions are met: no '%' and no 'xn-' subsequence.
  std::string buffer = std::string(input);
  // This next function checks that the result is ascii, but we are going to
  // to check anyhow with is_forbidden.
  // bool is_ascii =
  unicode::to_lower_ascii(buffer.data(), buffer.size());
  bool is_forbidden = unicode::contains_forbidden_domain_code_point(
      buffer.data(), buffer.size());
  if (is_forbidden == 0 && buffer.find("xn-") == std::string_view::npos) {
    // fast path
    host = std::move(buffer);
    if (checkers::is_ipv4(host.value())) {
      ada_log("parse_host fast path ipv4");
      return parse_ipv4(host.value());
    }
    ada_log("parse_host fast path ", *host);
    return true;
  }
  ada_log("parse_host calling to_ascii");
  is_valid = ada::unicode::to_ascii(host, input, input.find('%'));
  if (!is_valid) {
    ada_log("parse_host to_ascii returns false");
    return is_valid = false;
  }
  ada_log("parse_host to_ascii succeeded ", *host, " [", host->size(),
          " bytes]");

  if (std::any_of(host.value().begin(), host.value().end(),
                  ada::unicode::is_forbidden_domain_code_point)) {
    host = std::nullopt;
    return is_valid = false;
  }

  // If asciiDomain ends in a number, then return the result of IPv4 parsing
  // asciiDomain.
  if (checkers::is_ipv4(host.value())) {
    ada_log("parse_host got ipv4 ", *host);
    return parse_ipv4(host.value());
  }

  return true;
}

ada_really_inline void url::parse_path(std::string_view input) {
  ada_log("parse_path ", input);
  std::string tmp_buffer;
  std::string_view internal_input;
  if (unicode::has_tabs_or_newline(input)) {
    tmp_buffer = input;
    // Optimization opportunity: Instead of copying and then pruning, we could
    // just directly build the string from user_input.
    helpers::remove_ascii_tab_or_newline(tmp_buffer);
    internal_input = tmp_buffer;
  } else {
    internal_input = input;
  }

  // If url is special, then:
  if (is_special()) {
    if (internal_input.empty()) {
      path = "/";
    } else if ((internal_input[0] == '/') || (internal_input[0] == '\\')) {
      helpers::parse_prepared_path(internal_input.substr(1), type, path);
    } else {
      helpers::parse_prepared_path(internal_input, type, path);
    }
  } else if (!internal_input.empty()) {
    if (internal_input[0] == '/') {
      helpers::parse_prepared_path(internal_input.substr(1), type, path);
    } else {
      helpers::parse_prepared_path(internal_input, type, path);
    }
  } else {
    if (!host.has_value()) {
      path = "/";
    }
  }
}

[[nodiscard]] std::string url::to_string() const {
  if (!is_valid) {
    return "null";
  }
  std::string answer;
  auto back = std::back_insert_iterator(answer);
  answer.append("{\n");
  answer.append("\t\"protocol\":\"");
  helpers::encode_json(get_protocol(), back);
  answer.append("\",\n");
  if (has_credentials()) {
    answer.append("\t\"username\":\"");
    helpers::encode_json(username, back);
    answer.append("\",\n");
    answer.append("\t\"password\":\"");
    helpers::encode_json(password, back);
    answer.append("\",\n");
  }
  if (host.has_value()) {
    answer.append("\t\"host\":\"");
    helpers::encode_json(host.value(), back);
    answer.append("\",\n");
  }
  if (port.has_value()) {
    answer.append("\t\"port\":\"");
    answer.append(std::to_string(port.value()));
    answer.append("\",\n");
  }
  answer.append("\t\"path\":\"");
  helpers::encode_json(path, back);
  answer.append("\",\n");
  answer.append("\t\"opaque path\":");
  answer.append((has_opaque_path ? "true" : "false"));
  if (has_search()) {
    answer.append(",\n");
    answer.append("\t\"query\":\"");
    helpers::encode_json(query.value(), back);
    answer.append("\"");
  }
  if (hash.has_value()) {
    answer.append(",\n");
    answer.append("\t\"hash\":\"");
    helpers::encode_json(hash.value(), back);
    answer.append("\"");
  }
  answer.append("\n}");
  return answer;
}

[[nodiscard]] bool url::has_valid_domain() const noexcept {
  if (!host.has_value()) {
    return false;
  }
  return checkers::verify_dns_length(host.value());
}

[[nodiscard]] std::string url::get_origin() const noexcept {
  if (is_special()) {
    // Return a new opaque origin.
    if (type == scheme::FILE) {
      return "null";
    }
    return ada::helpers::concat(get_protocol(), "//", get_host());
  }

  if (non_special_scheme == "blob") {
    if (!path.empty()) {
      auto result = ada::parse<ada::url>(path);
      if (result &&
          (result->type == scheme::HTTP || result->type == scheme::HTTPS)) {
        // If pathURL's scheme is not "http" and not "https", then return a
        // new opaque origin.
        return ada::helpers::concat(result->get_protocol(), "//",
                                    result->get_host());
      }
    }
  }

  // Return a new opaque origin.
  return "null";
}

[[nodiscard]] std::string url::get_protocol() const noexcept {
  if (is_special()) {
    return helpers::concat(ada::scheme::details::is_special_list[type], ":");
  }
  // We only move the 'scheme' if it is non-special.
  return helpers::concat(non_special_scheme, ":");
}

[[nodiscard]] std::string url::get_host() const noexcept {
  // If url's host is null, then return the empty string.
  // If url's port is null, return url's host, serialized.
  // Return url's host, serialized, followed by U+003A (:) and url's port,
  // serialized.
  if (!host.has_value()) {
    return "";
  }
  if (port.has_value()) {
    return host.value() + ":" + get_port();
  }
  return host.value();
}

[[nodiscard]] std::string url::get_hostname() const noexcept {
  return host.value_or("");
}

[[nodiscard]] std::string url::get_search() const noexcept {
  // If this's URL's query is either null or the empty string, then return the
  // empty string. Return U+003F (?), followed by this's URL's query.
  return (!query.has_value() || (query.value().empty())) ? ""
                                                         : "?" + query.value();
}

[[nodiscard]] const std::string& url::get_username() const noexcept {
  return username;
}

[[nodiscard]] const std::string& url::get_password() const noexcept {
  return password;
}

[[nodiscard]] std::string url::get_port() const noexcept {
  return port.has_value() ? std::to_string(port.value()) : "";
}

[[nodiscard]] std::string url::get_hash() const noexcept {
  // If this's URL's fragment is either null or the empty string, then return
  // the empty string. Return U+0023 (#), followed by this's URL's fragment.
  return (!hash.has_value() || (hash.value().empty())) ? ""
                                                       : "#" + hash.value();
}

template <bool override_hostname>
bool url::set_host_or_hostname(const std::string_view input) {
  if (has_opaque_path) {
    return false;
  }

  std::optional<std::string> previous_host = host;
  std::optional<uint16_t> previous_port = port;

  size_t host_end_pos = input.find('#');
  std::string _host(input.data(), host_end_pos != std::string_view::npos
                                      ? host_end_pos
                                      : input.size());
  helpers::remove_ascii_tab_or_newline(_host);
  std::string_view new_host(_host);

  // If url's scheme is "file", then set state to file host state, instead of
  // host state.
  if (type != ada::scheme::type::FILE) {
    std::string_view host_view(_host.data(), _host.length());
    auto [location, found_colon] =
        helpers::get_host_delimiter_location(is_special(), host_view);

    // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
    // Note: the 'found_colon' value is true if and only if a colon was
    // encountered while not inside brackets.
    if (found_colon) {
      if constexpr (override_hostname) {
        return false;
      }
      std::string_view buffer = new_host.substr(location + 1);
      if (!buffer.empty()) {
        set_port(buffer);
      }
    }
    // If url is special and host_view is the empty string, validation error,
    // return failure. Otherwise, if state override is given, host_view is the
    // empty string, and either url includes credentials or url's port is
    // non-null, return.
    else if (host_view.empty() &&
             (is_special() || has_credentials() || port.has_value())) {
      return false;
    }

    // Let host be the result of host parsing host_view with url is not special.
    if (host_view.empty() && !is_special()) {
      host = "";
      return true;
    }

    bool succeeded = parse_host(host_view);
    if (!succeeded) {
      host = previous_host;
      update_base_port(previous_port);
    }
    return succeeded;
  }

  size_t location = new_host.find_first_of("/\\?");
  if (location != std::string_view::npos) {
    new_host.remove_suffix(new_host.length() - location);
  }

  if (new_host.empty()) {
    // Set url's host to the empty string.
    host = "";
  } else {
    // Let host be the result of host parsing buffer with url is not special.
    if (!parse_host(new_host)) {
      host = previous_host;
      update_base_port(previous_port);
      return false;
    }

    // If host is "localhost", then set host to the empty string.
    if (host.has_value() && host.value() == "localhost") {
      host = "";
    }
  }
  return true;
}

bool url::set_host(const std::string_view input) {
  return set_host_or_hostname<false>(input);
}

bool url::set_hostname(const std::string_view input) {
  return set_host_or_hostname<true>(input);
}

bool url::set_username(const std::string_view input) {
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  username = ada::unicode::percent_encode(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  return true;
}

bool url::set_password(const std::string_view input) {
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  password = ada::unicode::percent_encode(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  return true;
}

bool url::set_port(const std::string_view input) {
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  std::string trimmed(input);
  helpers::remove_ascii_tab_or_newline(trimmed);
  if (trimmed.empty()) {
    port = std::nullopt;
    return true;
  }

  if (!ada::unicode::is_ascii_digit(trimmed.front())) {
    return false;
  }

  auto non_digit_pos = std::find_if_not(trimmed.begin(), trimmed.end(),
                                        ada::unicode::is_ascii_digit);
  if (non_digit_pos != trimmed.end()) {
    trimmed.erase(non_digit_pos, trimmed.end());
  }

  // Input should not start with control characters.
  if (ada::unicode::is_c0_control_or_space(trimmed.front())) {
    return false;
  }

  // Revert changes if parse_port fails.
  std::optional<uint16_t> previous_port = port;
  parse_port(trimmed);
  if (is_valid) {
    return true;
  }
  port = previous_port;
  is_valid = true;
  return false;
}

void url::set_hash(const std::string_view input) {
  if (input.empty()) {
    hash = std::nullopt;
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '#' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);
  hash = unicode::percent_encode(new_value,
                                 ada::character_sets::FRAGMENT_PERCENT_ENCODE);
}

void url::set_search(const std::string_view input) {
  if (input.empty()) {
    query = std::nullopt;
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '?' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);

  auto query_percent_encode_set =
      is_special() ? ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE
                   : ada::character_sets::QUERY_PERCENT_ENCODE;

  query = ada::unicode::percent_encode(new_value, query_percent_encode_set);
}

bool url::set_pathname(const std::string_view input) {
  if (has_opaque_path) {
    return false;
  }
  path = "";
  parse_path(input);
  return true;
}

bool url::set_protocol(const std::string_view input) {
  std::string view(input);
  helpers::remove_ascii_tab_or_newline(view);
  if (view.empty()) {
    return true;
  }

  // Schemes should start with alpha values.
  if (!checkers::is_alpha(view[0])) {
    return false;
  }

  view.append(":");

  std::string::iterator pointer =
      std::ranges::find_if_not(view, unicode::is_alnum_plus);

  if (pointer != view.end() && *pointer == ':') {
    return parse_scheme<true>(
        std::string_view(view.data(), pointer - view.begin()));
  }
  return false;
}

bool url::set_href(const std::string_view input) {
  ada::result<ada::url> out = ada::parse<ada::url>(input);

  if (out) {
    *this = *out;
  }

  return out.has_value();
}

}  // namespace ada
