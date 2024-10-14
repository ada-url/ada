#include <string_view>
#include <cctype>

#include "ada.h"

namespace ada::data_url {

ada::data_url::data_url parse_data_url(std::string_view data_url) {
  auto out = ada::data_url::data_url();

  auto url = ada::parse<ada::url>(data_url, nullptr);

  // 1. Assert: dataURL’s scheme is "data".
  if (!url || url->get_protocol() != "data:") {
    out.is_valid = false;
    return out;
  }

  // 2. Let input be the result of running the URL serializer on dataURL with
  // exclude
  //    fragment set to true.
  url->set_hash({});
  auto input = url->get_href();

  // 3. Remove the leading "data:" from input.
  input.erase(0, 5);

  // 4. Let position point at the start of input.
  size_t position = 0;

  // 5. Let mimeType be the result of collecting a sequence of code points that
  // are
  //    not equal to U+002C (,), given position.
  auto mimetype = collect_sequence_of_code_points(',', input, position);
  auto mimetype_length = mimetype.length();

  // 6. Strip leading and trailing ASCII whitespace from mimeType.
  mimetype = removeASCIIWhiteSpace(mimetype, true, true);

  // 7. If position is past the end of input, then return failure.
  if (position >= input.length()) {
    out.is_valid = false;
    return out;
  }

  // 8. Advance position by 1.
  position++;

  // 9. Let encodedBody be the remainder of input.
  std::string encoded_body = input.substr(mimetype_length + 1);

  // 10. Let body be the percent-decoding of encodedBody.
  encoded_body =
      ada::unicode::percent_decode(encoded_body, encoded_body.find('%'));

  // 11. If mimeType ends with U+003B (;), followed by zero or more U+0020
  // SPACE,
  //     followed by an ASCII case-insensitive match for "base64", then:
  size_t last_semi_colon = input.find_last_of(';');

  if (last_semi_colon != std::string::npos) {
    size_t next_non_space = input.find_first_not_of(' ', last_semi_colon);

    out.essence = mimetype.substr(0, last_semi_colon);

    if (is_base64(mimetype)) {
      // 11.1. Let stringBody be the isomorphic decode of body.
      auto string_body = encoded_body;

      // 11.2. Set body to the forgiving-base64 decode of stringBody.
      // 11.3. If body is failure, then return failure.
      // TODO
      out.body = string_body;

      // 11.4. Remove the last 6 code points from mimeType.
      // 11.5. Remove trailing U+0020 SPACE code points from mimeType, if any.
      // 11.6. Remove the last U+003B (;) from mimeType.
      mimetype.erase(last_semi_colon);
    }
  }

  // 12. If mimeType starts with ";", then prepend "text/plain" to mimeType.
  if (mimetype.starts_with(';')) {
    mimetype = "text/plain" + mimetype;
  }

  return out;
}

std::string collect_sequence_of_code_points(char c, const std::string& input,
                                            size_t& position) {
  auto idx = input.find_first_of(c, position);
  size_t start = position;

  if (idx == std::string::npos) {
    position = reinterpret_cast<size_t>(input.length());
    return input.substr(start);
  }

  position = reinterpret_cast<size_t>(idx);
  return input.substr(start, position);
}

std::string removeASCIIWhiteSpace(const std::string& input, bool leading,
                                  bool trailing) {
  size_t lead = 0;
  size_t trail = input.length();

  if (leading) {
    while (lead < input.length() && isASCIIWhiteSpace(input[lead])) lead++;
  }

  if (trailing) {
    while (trail > 0 && isASCIIWhiteSpace(input[trail])) trail--;
  }

  return input.substr(lead, trail);
}

bool isASCIIWhiteSpace(char c) {
  return c == '\r' || c == '\n' || c == '\t' || c == '\f';
}

static constexpr bool is_base64(std::string_view input) {
  auto last_idx = input.find_last_of(';');
  if (last_idx != std::string_view::npos) {
    // TODO(@anonrig): Trim input
    auto res = input.substr(last_idx + 1);
    return res.size() == 6 && (res[0] | 0x20) == 'b' &&
           (res[1] | 0x20) == 'a' && (res[2] | 0x20) == 's' &&
           (res[3] | 0x20) == 'e' && (res[4] == '6') && (res[5] == '4');
  }
  return false;
}

}  // namespace ada::data_url
