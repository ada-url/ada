#include "ada.h"

#include <iostream>

namespace ada {

  ada_warn_unused url parse(std::string input,
                            std::optional<ada::url> base_url,
                            ada::encoding_type encoding,
                            std::optional<ada::state> state) noexcept {

    return ada::parser::parse_url(input, base_url, encoding, std::nullopt, state);
  }

  /*
   * The protocol setter steps are to basic URL parse the given value, followed by U+003A (:),
   * with this’s URL as url and scheme start state as state override.
   *
   * @see https://url.spec.whatwg.org/#dom-url-protocol
   */
  void set_scheme(ada::url &base, std::string input, ada::encoding_type encoding) noexcept {
    if (!input.empty()) {
      input.append(":");
    }
    auto result = ada::parser::parse_url(input, std::nullopt, encoding, base, SCHEME_START);

    if (result.is_valid && !result.scheme.empty()) {
      base.scheme = result.scheme;
    }
  }

} // namespace ada
