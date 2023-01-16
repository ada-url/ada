#include "ada.h"
#include "ada/character_sets.h"
#include "ada/checkers.h"
#include "ada/unicode.h"
#include "ada/url.h"

#include <array>
#include <algorithm>
#include <cstring>
#include <charconv>
#include <cstdlib>
#include <iostream>
#include <numeric>

#include <string_view>
#include <unicode/utypes.h>
#include <unicode/uidna.h>
#include <unicode/utf8.h>

namespace ada::parser {

  /**
   * @see https://url.spec.whatwg.org/#concept-domain-to-ascii
   *
   * The only difference between domain_to_ascii and to_ascii is that
   * to_ascii does not expect the input to be percent decoded. This is
   * mostly used to conform with the test suite.
   */
  std::optional<std::string> to_ascii(const std::string_view plain, const bool be_strict, size_t first_percent) {
    std::string percent_decoded_buffer;
    std::string_view input = plain;
    if(first_percent != std::string_view::npos) {
      percent_decoded_buffer = unicode::percent_decode(plain, first_percent);
      input = percent_decoded_buffer;
    }
    UErrorCode status = U_ZERO_ERROR;
    uint32_t options = UIDNA_CHECK_BIDI | UIDNA_CHECK_CONTEXTJ | UIDNA_NONTRANSITIONAL_TO_ASCII;

    if (be_strict) {
      options |= UIDNA_USE_STD3_RULES;
    }

    UIDNA* uidna = uidna_openUTS46(options, &status);
    if (U_FAILURE(status)) {
      return std::nullopt;
    }

    UIDNAInfo info = UIDNA_INFO_INITIALIZER;
    std::string result(255, ' ');
    int32_t length = uidna_nameToASCII_UTF8(uidna,
                                         input.data(),
                                         int32_t(input.length()),
                                         result.data(), int32_t(result.capacity()),
                                         &info,
                                         &status);

    if (status == U_BUFFER_OVERFLOW_ERROR) {
      status = U_ZERO_ERROR;
      result.resize(length);
      length = uidna_nameToASCII_UTF8(uidna,
                                     input.data(),
                                     int32_t(input.length()),
                                     result.data(), int32_t(result.capacity()),
                                     &info,
                                     &status);
    }

    // A label contains hyphen-minus ('-') in the third and fourth positions.
    info.errors &= ~UIDNA_ERROR_HYPHEN_3_4;
    // A label starts with a hyphen-minus ('-').
    info.errors &= ~UIDNA_ERROR_LEADING_HYPHEN;
    // A label ends with a hyphen-minus ('-').
    info.errors &= ~UIDNA_ERROR_TRAILING_HYPHEN;

    if (!be_strict) {
      // A non-final domain name label (or the whole domain name) is empty.
      info.errors &= ~UIDNA_ERROR_EMPTY_LABEL;
      // A domain name label is longer than 63 bytes.
      info.errors &= ~UIDNA_ERROR_LABEL_TOO_LONG;
      // A domain name is longer than 255 bytes in its storage form.
      info.errors &= ~UIDNA_ERROR_DOMAIN_NAME_TOO_LONG;
    }

    uidna_close(uidna);

    if (U_FAILURE(status) || info.errors != 0 || length == 0) {
      return std::nullopt;
    }

    result.resize(length);
    if(std::any_of(result.begin(), result.end(), ada::unicode::is_forbidden_domain_code_point)) { return std::nullopt; }

    return result;
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-opaque-host-parser
   */
  bool parse_opaque_host(std::optional<std::string>& out, std::string_view input) {
    if (std::any_of(input.begin(), input.end(), ada::unicode::is_forbidden_host_code_point)) {
      return false;
    }

    // Return the result of running UTF-8 percent-encode on input using the C0 control percent-encode set.
    out = ada::unicode::percent_encode(input, ada::character_sets::C0_CONTROL_PERCENT_ENCODE);
    return true;
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-ipv4-parser
   */
  bool parse_ipv4(std::optional<std::string>& out, std::string_view input) {
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
        if (r.ec != std::errc()) { return false; }
        input.remove_prefix(r.ptr-input.data());
      }
      if(input.empty()) {
        // We have the last value.
        // At this stage, ipv4 contains digit_count*8 bits.
        // So we have 32-digit_count*8 bits left.
        if(result > (uint64_t(1)<<(32-digit_count*8))) { return false; }
        ipv4 <<=(32-digit_count*8);
        ipv4 |= result;
        goto final;
      } else {
        // There is more, so that the value must no be larger than 255
        // and we must have a '.'.
        if ((result>255) || (input[0]!='.')) { return false; }
        ipv4 <<=8;
        ipv4 |= result;
        input.remove_prefix(1); // remove '.'
      }
    }
    if((digit_count != 4) || (!input.empty())) {return false; }
    final:
    // We could also check result.ptr to see where the parsing ended.
    out = ada::serializers::ipv4(ipv4);
    return true;
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-ipv6-parser
   */
  bool parse_ipv6(std::optional<std::string>& out, std::string_view input) {
  #if ADA_DEVELOP_MODE
    // prove that this is not necessary:
    if(input.empty()) { return false; }
  #endif
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
        return false;
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
        return false;
      }

      // If c is U+003A (:), then:
      if (*pointer == ':') {
        // If compress is non-null, validation error, return failure.
        if (compress.has_value()) {
          return false;
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
          return false;
        }

        // Decrease pointer by length.
        pointer -= length;

        // If pieceIndex is greater than 6, validation error, return failure.
        if (piece_index > 6) {
          return false;
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
              return false;
            }
          }

          // If c is not an ASCII digit, validation error, return failure.
          if (!checkers::is_digit(*pointer)) {
            return false;
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
              return false;
            }
            // Otherwise, set ipv4Piece to ipv4Piece × 10 + number.
            else {
              ipv4_piece = *ipv4_piece * 10 + number;
            }

            // If ipv4Piece is greater than 255, validation error, return failure.
            if (ipv4_piece > 255) {
              return false;
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
          return false;
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
          return false;
        }
      }
      // Otherwise, if c is not the EOF code point, validation error, return failure.
      else if (pointer != input.end()) {
        return false;
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
      return false;
    }

    out = ada::serializers::ipv6(address);
    return true;
  }

  /**
   * @see https://url.spec.whatwg.org/#host-parsing
   */
  bool parse_host(std::optional<std::string>& out, const std::string_view input, bool is_not_special, bool input_is_ascii) {
    //
    // Note: this function assumes that parse_host is not empty. Make sure we can
    // guarantee that.
    //
    // If input starts with U+005B ([), then:
    if (input[0] == '[') {
      // If input does not end with U+005D (]), validation error, return failure.
      if (input.back() != ']') {
        return false;
      }

      // Return the result of IPv6 parsing input with its leading U+005B ([) and trailing U+005D (]) removed.
      return parse_ipv6(out, std::string_view(input.begin() + 1, input.end() - input.begin() - 2));
    }

    // If isNotSpecial is true, then return the result of opaque-host parsing input.
    if (is_not_special) {
      return parse_opaque_host(out, input);
    }

    // Let domain be the result of running UTF-8 decode without BOM on the percent-decoding of input.
    // Let asciiDomain be the result of running domain to ASCII with domain and false.
    // The most common case is an ASCII input, in which case we do not need to call the expensive 'to_ascii'
    // if a few conditions are met: no '%' and no 'xn-' subsequence.
    size_t first_percent = input.find('%');
    // if simple_case is true, there is a good chance we might be able to use the fast path.
    bool simple_case = input_is_ascii && (first_percent == std::string_view::npos);

    // This function attemps to convert an ASCII string to a lower-case version.
    // Once the lower cased version has been materialized, we check for the presence
    // of the substring 'xn-', if it is found (unlikely), we then call the expensive 'to_ascii'.
    auto to_lower_ascii_string = [first_percent](std::string_view view) -> std::optional<std::string> {
      if(std::any_of(view.begin(), view.end(), ada::unicode::is_forbidden_domain_code_point)) { return std::nullopt; }
      std::string result(view);
      std::transform(result.begin(), result.end(), result.begin(),[](char c) -> char {
        return (uint8_t((c|0x20) - 0x61) <= 25 ? (c|0x20) : c);}
      );
      return (result.find("xn-") == std::string_view::npos) ? result : to_ascii(view, false, first_percent);
    };
    // In the simple case, we call to_lower_ascii_string above, or else, we fall back on the expensive case.
    out = simple_case ? to_lower_ascii_string(input) : to_ascii(input, false, first_percent);

    // If asciiDomain is failure, validation error, return failure.
    if (!out.has_value()) {
      return false;
    }

    // If asciiDomain ends in a number, then return the result of IPv4 parsing asciiDomain.
    auto is_ipv4 = [](std::string_view view) {
      size_t last_dot = view.rfind('.');
      if(last_dot == view.size() - 1) {
        view.remove_suffix(1);
        last_dot = view.rfind('.');
      }
      std::string_view number = (last_dot == std::string_view::npos) ? view : view.substr(last_dot+1);
      if(number.empty()) { return false; }
      /** Optimization opportunity: we have basically identified the last number of the
      ipv4 if we return true here. We might as well parse it and have at least one
      number parsed when we get to parse_ipv4. */
      if(std::all_of(number.begin(), number.end(), ada::checkers::is_digit)) { return true; }
      return (checkers::has_hex_prefix(number) && std::all_of(number.begin()+2, number.end(), ::ada::unicode::is_lowercase_hex));
    };
    if(is_ipv4(*out)) {
      return parse_ipv4(out, *out);
    }
    return true;
  }

  url parse_url(std::string_view user_input,
                std::optional<ada::url> base_url,
                ada::encoding_type encoding,
                std::optional<ada::url> optional_url,
                std::optional<ada::state> state_override) {
    // Let state be state override if given, or scheme start state otherwise.
    ada::state state = state_override.value_or(ada::state::SCHEME_START);

    /**
     * Design concern: We take an optional_url as a parameter. Yet optional_url
     * is only ever used on the next line.
     */

    // If we have anything in optional_url, then it was copied there.
    // As much as possible, we do not want relatively expensive constructor in our
    // main function (parse_url).
    ada::url url = optional_url.has_value() ? std::move(optional_url.value()) : ada::url();
    // From this point forward, optional_url should not be used.

    // most input strings will be ASCII which may enable some optimizations.
    const bool is_ascii = !user_input.empty() && 128>(std::reduce(user_input.begin(), user_input.end(), uint8_t(user_input[0]), std::bit_or<uint8_t>()));

    std::string tmp_buffer;
    std::string_view internal_input;
    if(std::any_of(user_input.begin(), user_input.end(), ada::unicode::is_ascii_tab_or_newline)) {
      tmp_buffer = user_input;
      // Optimization opportunity: Instead of copying and then pruning, we could just directly
      // build the string from user_input.
      helpers::remove_ascii_tab_or_newline(tmp_buffer);
      internal_input = tmp_buffer;
    } else {
      internal_input = user_input;
    }

    // TODO: Find a better way to trim from leading and trailing.
    std::string_view::iterator pointer_start = std::find_if_not(internal_input.begin(), internal_input.end(), ada::unicode::is_c0_control_or_space);
    if (pointer_start == internal_input.end()) { pointer_start = internal_input.begin(); }
    std::string_view::iterator pointer_end = std::find_if_not(internal_input.rbegin(), std::make_reverse_iterator(pointer_start), ada::unicode::is_c0_control_or_space).base();

    std::string_view url_data(pointer_start, pointer_end - pointer_start);

    // Optimization opportunity. Most websites does not have fragment.
    std::optional<std::string_view> fragment = helpers::prune_fragment(url_data);
    if(fragment.has_value()) {
      url.fragment = unicode::percent_encode(*fragment,
                                             ada::character_sets::FRAGMENT_PERCENT_ENCODE);
    }

    // Here url_data no longer has its fragment.
    // The rest of the code might work with std::string_view, not pointers, it would
    // be easier to follow. But because we don't want to change everything, let us
    // bring back the pointers.
    pointer_start = state_override.has_value() ? internal_input.begin() : url_data.begin();
    pointer_end = state_override.has_value() ? internal_input.end() : url_data.end();

    // most URLs have no @. Having no @ tells us that we don't have to worry about AUTHORITY. Of course,
    // we could have @ and still not have to worry about AUTHORITY.
    // TODO: Instead of just collecting a bool, collect the location of the '@' and do something useful with it.
    // TODO: We could do various processing early on, using a single pass over the string to collect
    // information about it, e.g., telling us whether there is a @ and if so, where (or how many).
    const bool contains_ampersand = (std::find(pointer_start, pointer_end, '@') != pointer_end);

    // Let pointer be a pointer for input.
    std::string_view::iterator pointer = pointer_start;

    // Keep running the following state machine by switching on state.
    // If after a run pointer points to the EOF code point, go to the next step.
    // Otherwise, increase pointer by 1 and continue with the state machine.
    for (; pointer <= pointer_end; pointer++) {
      ///////////////////////////////////////////////////////////////////////
      // Important: we can't have 'pointer == pointer_end' and then dereference
      // the pointer so the loop condition pointer <= pointer_end is a problem.
      //
      // The terrible thing is that dereferencing a pointer that is out of
      // range may work in practice, maybe almost always, and then we
      // end up with a random non-reproducible crash or bug.
      ///////////////////////////////////////////////////////////////////////
      switch (state) {
        case ada::state::SCHEME_START: {
          // If c is an ASCII alpha, append c, lowercased, to buffer, and set state to scheme state.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer != pointer_end) && checkers::is_alpha(*pointer)) {
            state = ada::state::SCHEME;
            pointer--;
          }
          // Otherwise, if state override is not given, set state to no scheme state and decrease pointer by 1.
          else {
            state = ada::state::NO_SCHEME;
            pointer--;
          }

          break;
        }
        case ada::state::SCHEME: {
          // If c is an ASCII alphanumeric, U+002B (+), U+002D (-), or U+002E (.), append c, lowercased, to buffer.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          pointer = std::find_if_not(pointer, pointer_end, ada::unicode::is_alnum_plus);
          // Otherwise, if c is U+003A (:), then:
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer != pointer_end) && (*pointer == ':')) {

            // Instead of copying and then changing the case,
            // we could directly append lower-cased to the string, thus doing one pass.
            std::string _buffer;
            std::transform(pointer_start, pointer, std::back_inserter(_buffer),
                [](char c) -> char { return (uint8_t((c|0x20) - 0x61) <= 25 ? (c|0x20) : c);});

            // If state override is given, then:
            if (state_override.has_value()) {
              // If url’s scheme is a special scheme and buffer is not a special scheme, then return.
              // If url’s scheme is not a special scheme and buffer is a special scheme, then return.
              if (url.is_special() != ada::scheme::is_special(_buffer)) {
                return url;
              }

              // If url includes credentials or has a non-null port, and buffer is "file", then return.
              if ((url.includes_credentials() || url.port.has_value()) && _buffer == "file") {
                return url;
              }

              // If url’s scheme is "file" and its host is an empty host, then return.
              // An empty host is the empty string.
              if (url.scheme == "file" && url.host.has_value() && url.host.value().empty()) {
                return url;
              }
            }

            // Set url’s scheme to buffer.
            url.scheme = _buffer;

            // If state override is given, then:
            if (state_override.has_value()) {
              // This is uncommon.
              uint16_t urls_scheme_port = ada::scheme::get_special_port(url.scheme);

              if (urls_scheme_port) {
                // If url’s port is url’s scheme’s default port, then set url’s port to null.
                if (url.port.has_value() && *url.port == urls_scheme_port) {
                  url.port = std::nullopt;
                }
              }

              return url;
            }

            // If url’s scheme is "file", then:
            if (url.scheme == "file") {
              // Set state to file state.
              state = ada::state::FILE;
            }
            // Otherwise, if url is special, base is non-null, and base’s scheme is url’s scheme:
            // Note: Doing base_url->scheme is unsafe if base_url.has_value() is false.
            else if (url.is_special() && base_url.has_value() && base_url->scheme == url.scheme) {
              // Set state to special relative or authority state.
              state = ada::state::SPECIAL_RELATIVE_OR_AUTHORITY;
            }
            // Otherwise, if url is special, set state to special authority slashes state.
            else if (url.is_special()) {
              state = ada::state::SPECIAL_AUTHORITY_SLASHES;
            }
            // Otherwise, if remaining starts with an U+002F (/), set state to path or authority state
            // and increase pointer by 1.
            else if (std::distance(pointer, pointer_end) > 0 && pointer[1] == '/') {
              state = ada::state::PATH_OR_AUTHORITY;
              pointer++;
            }
            // Otherwise, set url’s path to the empty string and set state to opaque path state.
            else {
              state = ada::state::OPAQUE_PATH;
            }
          }
          // Otherwise, if state override is not given, set buffer to the empty string, state to no scheme state,
          // and start over (from the first code point in input).
          else if (!state_override.has_value()) {
            state = ada::state::NO_SCHEME;
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
        case ada::state::NO_SCHEME: {
          // If base is null, or base has an opaque path and c is not U+0023 (#), validation error, return failure.
          if (!base_url.has_value() || (base_url->has_opaque_path && (pointer != pointer_end))) {
            url.is_valid = false;
            return url;
          }
          // Otherwise, if base has an opaque path and c is U+0023 (#),
          // set url’s scheme to base’s scheme, url’s path to base’s path, url’s query to base’s query,
          // url’s fragment to the empty string, and set state to fragment state.
          else if (base_url->has_opaque_path && url.fragment.has_value() && pointer == pointer_end) {
            url.scheme = base_url->scheme;
            url.path = base_url->path;
            url.has_opaque_path = base_url->has_opaque_path;
            url.query = base_url->query;
            return url;
          }
          // Otherwise, if base’s scheme is not "file", set state to relative state and decrease pointer by 1.
          else if (base_url->scheme != "file") {
            state = ada::state::RELATIVE;
            pointer--;
          }
          // Otherwise, set state to file state and decrease pointer by 1.
          else {
            state = ada::state::FILE;
            pointer--;
          }

          break;
        }
        case ada::state::AUTHORITY: {
          if(!contains_ampersand) {
            // TODO: This is a waste of time, we should never have arrived here.
            pointer--;
            state = ada::state::HOST;
            break;
          }
          bool at_sign_seen{false};
          bool password_token_seen{false};
          do {
            std::string_view view(pointer, size_t(pointer_end-pointer));
            size_t location = url.is_special() ? view.find_first_of("@/?\\") : view.find_first_of("@/?");
            std::string_view authority_view(view.data(), (location != std::string_view::npos) ? location : view.size());
            pointer = (location == std::string_view::npos) ? pointer_end : pointer + location;
            // If c is U+0040 (@), then:
            // Note: we cannot access *pointer safely if (pointer == pointer_end).
            if ((pointer != pointer_end) && (*pointer == '@')) {
              // If atSignSeen is true, then prepend "%40" to buffer.
              if (at_sign_seen) {
                if (password_token_seen) {
                  url.password += "%40";
                } else {
                  url.username += "%40";
                }
              }

              // Set atSignSeen to true.
              at_sign_seen = true;

              // For each codePoint in authority_buffer:
              for (auto code_point: authority_view) {
                // If codePoint is U+003A (:) and passwordTokenSeen is false, then set passwordTokenSeen to true and continue.
                if (code_point == ':' && !password_token_seen) {
                  password_token_seen = true;
                  continue;
                }

                // Let encodedCodePoints be the result of running UTF-8 percent-encode codePoint using the userinfo percent-encode set.
                // If passwordTokenSeen is true, then append encodedCodePoints to url’s password.
                if (password_token_seen) {
                  unicode::percent_encode_character(code_point, character_sets::USERINFO_PERCENT_ENCODE, url.password);
                }
                // Otherwise, append encodedCodePoints to url’s username.
                else {
                  unicode::percent_encode_character(code_point, character_sets::USERINFO_PERCENT_ENCODE, url.username);
                }
              }
            }
            // Otherwise, if one of the following is true:
            // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
            // - url is special and c is U+005C (\)
            else if (pointer == pointer_end || *pointer == '/' || *pointer == '?' || (url.is_special() && *pointer == '\\')) {
              // If atSignSeen is true and authority_view is the empty string, validation error, return failure.
              if (at_sign_seen && authority_view.empty()) {
                url.is_valid = false;
                return url;
              }
              // Decrease pointer by the number of code points in buffer plus one,
              // set buffer to the empty string, and set state to host state.
              pointer -= authority_view.length() + 1;
              state = ada::state::HOST;
              break;
            }
          
            if(pointer == pointer_end) { break; }
            pointer++;
          } while(true);

          break;
        }
        case ada::state::SPECIAL_RELATIVE_OR_AUTHORITY: {
          // If c is U+002F (/) and remaining starts with U+002F (/),
          // then set state to special authority ignore slashes state and increase pointer by 1.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          std::string_view view (pointer, size_t(pointer_end-pointer));
          if (ada::checkers::begins_with(view, "//")) {
            state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
            pointer++;
          }
          // Otherwise, validation error, set state to relative state and decrease pointer by 1.
          else {
            state = ada::state::RELATIVE;
            pointer--;
          }

          break;
        }
        case ada::state::PATH_OR_AUTHORITY: {
          // If c is U+002F (/), then set state to authority state.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer != pointer_end) && (*pointer == '/')) {
            state = ada::state::AUTHORITY;
          }
          // Otherwise, set state to path state, and decrease pointer by 1.
          else {
            state = ada::state::PATH;
            pointer--;
          }

          break;
        }
        case ada::state::RELATIVE: {
          // Set url’s scheme to base’s scheme.
#if ADA_DEVELOP_MODE
          ///////
          // next line is for development purposes, to ensure safety.
          ///////
          if(!base_url.has_value()) { throw std::runtime_error("Internal error.\n"); }
#endif
          url.scheme = base_url->scheme;

          // If c is U+002F (/), then set state to relative slash state.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer != pointer_end) && (*pointer == '/')) {
            state = ada::state::RELATIVE_SLASH;
          }
          // Otherwise, if url is special and c is U+005C (\), validation error, set state to relative slash state.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          else if (url.is_special() && (pointer != pointer_end) && (*pointer == '\\')) {
            state = ada::state::RELATIVE_SLASH;
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
            url.has_opaque_path = base_url->has_opaque_path;
            url.query = base_url->query;

            // If c is U+003F (?), then set url’s query to the empty string, and state to query state.
            if (*pointer == '?') {
              url.query = "";
              state = ada::state::QUERY;
            }
            // Otherwise, if c is not the EOF code point:
            else if (pointer != pointer_end) {
              // Set url’s query to null.
              url.query = std::nullopt;

              // Shorten url’s path.
              helpers::shorten_path(url);

              // Set state to path state and decrease pointer by 1.
              state = ada::state::PATH;
              pointer--;
            }
          }

          break;
        }
        case ada::state::RELATIVE_SLASH: {
          // If url is special and c is U+002F (/) or U+005C (\), then:
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if (url.is_special() && (pointer != pointer_end) && (*pointer == '/' || *pointer =='\\')) {
            // Set state to special authority ignore slashes state.
            state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
          }
          // Otherwise, if c is U+002F (/), then set state to authority state.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          else if ((pointer != pointer_end) && (*pointer == '/')) {
            state = ada::state::AUTHORITY;
          }
          // Otherwise, set
          // - url’s username to base’s username,
          // - url’s password to base’s password,
          // - url’s host to base’s host,
          // - url’s port to base’s port,
          // - state to path state, and then, decrease pointer by 1.
          else {
#if ADA_DEVELOP_MODE
            //////////
            ///// For development purposes, to ensure safey:
            /////////////
            if(!base_url.has_value()) { throw std::runtime_error("Internal error.\n"); }
#endif
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
            state = ada::state::PATH;
            pointer--;
          }

          break;
        }
        case ada::state::SPECIAL_AUTHORITY_SLASHES: {
          // If c is U+002F (/) and remaining starts with U+002F (/),
          // then set state to special authority ignore slashes state and increase pointer by 1.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
           std::string_view view (pointer, size_t(pointer_end-pointer));
          if (ada::checkers::begins_with(view, "//")) {
            pointer++;
          }
          // Otherwise, validation error, set state to special authority ignore slashes state and decrease pointer by 1.
          else {
            pointer--;
          }

          state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;

          break; /** Here we should just fall through !!! */
        }
        case ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES: {
          // If c is neither U+002F (/) nor U+005C (\), then set state to authority state and decrease pointer by 1.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer == pointer_end) || ((*pointer != '/') && (*pointer != '\\'))) {
            state = ada::state::AUTHORITY;
            pointer--;
          }

          break;
        }
        case ada::state::QUERY: {
          // If encoding is not UTF-8 and one of the following is true:
          // - url is not special
          // - url’s scheme is "ws" or "wss"
          if (encoding != ada::encoding_type::UTF8) {
            if (!url.is_special() || url.scheme == "ws" || url.scheme == "wss") {
              // then set encoding to UTF-8.
              encoding = ada::encoding_type::UTF8;
            }
          }

          // Let queryPercentEncodeSet be the special-query percent-encode set if url is special;
          // otherwise the query percent-encode set.
          auto query_percent_encode_set = url.is_special() ?
                                ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE :
                                ada::character_sets::QUERY_PERCENT_ENCODE;

          // Percent-encode after encoding, with encoding, buffer, and queryPercentEncodeSet,
          // and append the result to url’s query.
          url.query = ada::unicode::percent_encode(std::string_view(pointer, pointer_end-pointer), query_percent_encode_set);

          return url;
        }
        case ada::state::HOST: {
          bool inside_brackets{false};

          // Given a call to parse_url, we should get here at most *ONCE*.
          // There is the business with '[', but that's no problem.
          std::string_view view(pointer, size_t(pointer_end-pointer));
          size_t location = url.is_special() ? view.find_first_of(":[/?\\") : view.find_first_of(":[/?");

          // Next while loop is almost never taken!
          while((location != std::string_view::npos) && (view[location] == '[')) {
            location = view.find(']',location);
            if(location == std::string_view::npos) {
              inside_brackets = true;
              /** 
               * TODO: Ok. So if we arrive here then view has an unclosed [,
               * Is the URL valid???
               */
            } else {
              location = url.is_special() ? view.find_first_of(":[/?\\#", location) : view.find_first_of(":[/?#", location);
            }
          }
          std::string_view host_view(view.data(), (location != std::string_view::npos) ? location :view.size());
          pointer = (location != std::string_view::npos) ? pointer + location : pointer_end;


          // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer != pointer_end) && (*pointer == ':') && !inside_brackets) {
            // If buffer is the empty string, validation error, return failure.
            if (host_view.empty()) {
              url.is_valid = false;
              return url;
            }
            // If state override is given and state override is hostname state, then return.
            else if (state_override.has_value() && state_override == ada::state::HOST) {
              return url;
            }

            // Let host be the result of host parsing buffer with url is not special.
            url.is_valid = parse_host(url.host, host_view, !url.is_special(), is_ascii);

            // Set url’s host to host, buffer to the empty string, and state to port state.
            state = ada::state::PORT;
          }
          // Otherwise, if one of the following is true:
          // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
          // - url is special and c is U+005C (\)
          else if (pointer == pointer_end || *pointer == '/' || *pointer == '?' || (url.is_special() && *pointer == '\\')) {
            // then decrease pointer by 1, and then:
            pointer--;

            // If url is special and host_view is the empty string, validation error, return failure.
            if (url.is_special() && host_view.empty()) {
              url.is_valid = false;
              return url;
            }
            // Otherwise, if state override is given, host_view is the empty string,
            // and either url includes credentials or url’s port is non-null, return.
            else if (state_override.has_value() && host_view.empty() && (url.includes_credentials() || url.port.has_value())) {
              return url;
            }

            // Let host be the result of host parsing host_view with url is not special.
            url.is_valid = parse_host(url.host, host_view, !url.is_special(), is_ascii);

            // Set url’s host to host, and state to path start state.
            state = ada::state::PATH_START;

            // If state override is given, then return.
            if (state_override) {
              return url;
            }
          }
          break;
        }
        case ada::state::OPAQUE_PATH: {
          // If c is U+003F (?), then set url’s query to the empty string and state to query state.
          std::string_view view(pointer, size_t(pointer_end-pointer));
          size_t location = view.find('?');
          if(location != std::string_view::npos) {
            view.remove_suffix(location);
            state = ada::state::QUERY;
            pointer += location;
          } else {
            // TODO: we can probably just exit here.
            pointer = pointer_end;
          }
          url.has_opaque_path = true;
          url.path = unicode::percent_encode(view, character_sets::C0_CONTROL_PERCENT_ENCODE);
          break;
        }
        case ada::state::PORT: {
          auto out = helpers::parse_port(std::string_view(pointer, pointer_end - pointer),
                                         state,
                                         url.is_valid,
                                         url.is_special());

          if (out.has_value()) {
            if (url.scheme_default_port() == out) {
              url.port = std::nullopt;
            } else {
              url.port = out;
            }
          }

          break;
        }
        case ada::state::PATH_START: {
          // If url is special, then:
          if (url.is_special()) {
            // Set state to path state.
            state = ada::state::PATH;

            // If c is neither U+002F (/) nor U+005C (\), then decrease pointer by 1.
            if (*pointer != '/' && *pointer != '\\') {
              pointer--;
            }
          }
          // Otherwise, if state override is not given and c is U+003F (?),
          // set url’s query to the empty string and state to query state.
          else if (!state_override.has_value() && *pointer == '?') {
            state = ada::state::QUERY;
          }
          // Otherwise, if c is not the EOF code point:
          else if (pointer != pointer_end) {
            // Set state to path state.
            state = ada::state::PATH;

            // If c is not U+002F (/), then decrease pointer by 1.
            if (*pointer != '/') {
              pointer--;
            }
          }
          // Otherwise, if state override is given and url’s host is null, append the empty string to url’s path.
          else if (state_override.has_value() && !url.host.has_value()) {
            // To append to a list that is not an ordered set is to add the given item to the end of the list.
            url.path += "/";
          }

          break;
        }
        case ada::state::PATH: {
          // If one of the following is true:
          // - c is the EOF code point or U+002F (/)
          // - url is special and c is U+005C (\)
          // - state override is not given and c is U+003F (?) or U+0023 (#)
          do {
            std::string_view view(pointer, size_t(pointer_end-pointer));
            size_t location = url.is_special() ? (!state_override.has_value() ? view.find_first_of("/\\?") : view.find_first_of("/\\")) : (!state_override.has_value() ? view.find_first_of("/?") : view.find_first_of("/"));
            std::string_view path_view(pointer, (location != std::string_view::npos) ? location :view.size());
            std::string path_buffer = ada::unicode::percent_encode(path_view, character_sets::PATH_PERCENT_ENCODE);

            pointer = (location == std::string_view::npos) ? pointer_end : pointer + location;
            // If path_buffer is a double-dot path segment, then:
            if (unicode::is_double_dot_path_segment(path_buffer)) {
              // Shorten url’s path.
              helpers::shorten_path(url);

              // If neither c is U+002F (/), nor url is special and c is U+005C (\),
              // append the empty string to url’s path.
              if (*pointer != '/' && !(url.is_special() && *pointer == '\\')) {
                url.path += "/";
              }
            }
            // Otherwise, if path_buffer is a single-dot path segment and if neither c is U+002F (/),
            // nor url is special and c is U+005C (\), append the empty string to url’s path.
            else if (unicode::is_single_dot_path_segment(path_buffer) && *pointer != '/' && !(url.is_special() && *pointer == '\\')) {
              url.path += "/";
            }
            // Otherwise, if path_buffer is not a single-dot path segment, then:
            else if (!unicode::is_single_dot_path_segment(path_buffer)) {
              // If url’s scheme is "file", url’s path is empty, and path_buffer is a Windows drive letter,
              // then replace the second code point in path_buffer with U+003A (:).
              if (url.scheme == "file" && url.path.empty() && checkers::is_windows_drive_letter(path_buffer)){
                path_buffer[1] = ':';
              }

              // Append path_buffer to url’s path.
              url.path += "/" + path_buffer;
            }

            // If c is U+003F (?), then set url’s query to the empty string and state to query state.
            if (*pointer == '?') {
              state = ada::state::QUERY;
              break;
            }
            if(pointer == pointer_end) { break; }
            pointer++;
          } while(true);
          break;
        }
        case ada::state::FILE_SLASH: {
          // If c is U+002F (/) or U+005C (\), then:
          if (*pointer == '/' || *pointer == '\\') {
            // Set state to file host state.
            state = ada::state::FILE_HOST;
          }
          // Otherwise:
          else {
            // If base is non-null and base’s scheme is "file", then:
            // Note: it is unsafe to do base_url->scheme unless you know that
            // base_url_has_value() is true.
            if (base_url.has_value() && base_url.has_value() && base_url->scheme == "file") {
              // Set url’s host to base’s host.
              url.host = base_url->host;

              // If the code point substring from pointer to the end of input does not start with
              // a Windows drive letter and base’s path[0] is a normalized Windows drive letter,
              // then append base’s path[0] to url’s path.
              if (std::distance(pointer, pointer_end) > 0 && !base_url->path.empty()) {
                if (!checkers::is_windows_drive_letter({pointer, size_t(pointer_end - pointer)})) {
                  std::string first_base_url_path = base_url->path.substr(1, base_url->path.find_first_of('/', 1));

                  // Optimization opportunity: Get rid of initializing a std::string
                  if (checkers::is_normalized_windows_drive_letter(first_base_url_path)) {
                    url.path += "/" + first_base_url_path;
                  }
                }
              }
            }

            // Set state to path state, and decrease pointer by 1.
            state = ada::state::PATH;
            pointer--;
          }

          break;
        }
        case ada::state::FILE_HOST: {
          std::string_view view(pointer, size_t(pointer_end-pointer));
          size_t location = view.find_first_of("/\\?");
          std::string_view file_host_buffer(view.data(), (location != std::string_view::npos) ? location : view.size());
          pointer += location - 1;

          if (!state_override.has_value() && checkers::is_windows_drive_letter(file_host_buffer)) {
            state = ada::state::PATH;
          }
          else if (file_host_buffer.empty()) {
            // Set url’s host to the empty string.
            url.host = "";

            // If state override is given, then return.
            if (state_override.has_value()) {
              return url;
            }

            // Set state to path start state.
            state = ada::state::PATH_START;
          }
          else {
            // Let host be the result of host parsing buffer with url is not special.
            url.is_valid = parse_host(url.host, file_host_buffer, !url.is_special(), is_ascii);

            // If host is "localhost", then set host to the empty string.
            if (url.host.has_value() && url.host.value() == "localhost") {
              url.host = "";
            }

            // If state override is given, then return.
            if (state_override.has_value()) {
              return url;
            }

            // Set buffer to the empty string and state to path start state.
            state = ada::state::PATH_START;
          }

          break;
        }
        case ada::state::FILE: {
          // Set url’s scheme to "file".
          url.scheme = "file";

          // Set url’s host to the empty string.
          url.host = "";

          // If c is U+002F (/) or U+005C (\), then:
          if (*pointer == '/' || *pointer == '\\') {
            // Set state to file slash state.
            state = ada::state::FILE_SLASH;
          }
          // Otherwise, if base is non-null and base’s scheme is "file":
          else if (base_url.has_value() && base_url->scheme == "file") {
            // Set url’s host to base’s host, url’s path to a clone of base’s path, and url’s query to base’s query.
            url.host = base_url->host;
            url.path = base_url->path;
            url.has_opaque_path = base_url->has_opaque_path;
            url.query = base_url->query;

            // If c is U+003F (?), then set url’s query to the empty string and state to query state.
            if (*pointer == '?') {
              state = ada::state::QUERY;
            }
            // Otherwise, if c is not the EOF code point:
            else if (pointer != pointer_end) {
              // Set url’s query to null.
              url.query = std::nullopt;

              // If the code point substring from pointer to the end of input does not start with a
              // Windows drive letter, then shorten url’s path.
              if (std::distance(pointer, pointer_end) >= 2 && !checkers::is_windows_drive_letter(std::string_view(pointer, 2))) {
                helpers::shorten_path(url);
              }
              // Otherwise:
              else {
                // Set url’s path to an empty list.
                url.path = "";
                url.has_opaque_path = true;
              }

              // Set state to path state and decrease pointer by 1.
              state = ada::state::PATH;
              pointer--;
            }
          }
          // Otherwise, set state to path state, and decrease pointer by 1.
          else {
            state = ada::state::PATH;
            pointer--;
          }

          break;
        }
        default:
          ada::unreachable();
      }
    }

    return url;
  }

} // namespace ada::parser
