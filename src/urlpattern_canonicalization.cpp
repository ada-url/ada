#include "ada/urlpattern_canonicalization.h"

#include "ada/ada_idna.h"
#include "ada/implementation.h"
#include <string>

namespace ada::urlpattern {

// https://wicg.githu b.io/urlpattern/#canonicalize-a-protocol
// TODO: maybe make it receive a utf8 string at this point already
std::u32string_view canonicalize_protocol(std::u32string_view protocol) {
  // If value is the empty string, return value.
  if (protocol.empty()) return protocol;

  // Let dummyURL be a new URL record.
  // Let parseResult be the result of running the basic URL parser given value
  // followed by "://dummy.test", with dummyURL as url.

  // TODO: make it cheaper
  std::u32string url = std::u32string(protocol) + U"://dummy.test";

  auto utf8_size = ada::idna::utf8_length_from_utf32(url.data(), url.size());
  std::string final_utf8_url(utf8_size, '\0');
  ada::idna::utf32_to_utf8(url.data(), url.size(), final_utf8_url.data());

  if (ada::can_parse(final_utf8_url)) {
    return protocol;
  }
  throw std::invalid_argument("invalid protocol scheme");
}

}  // namespace ada::urlpattern