#include "ada.h"
#include "parser.h"

namespace ada {

  ada_warn_unused ada::URL parse(std::string_view input, std::optional<ada::URL> base_url, ada::encoding_type encoding) noexcept {
    auto parser = new Parser(input, base_url, encoding, SCHEME_START);

    return parser->getURL();
  }

} // namespace ada
