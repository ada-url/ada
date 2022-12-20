#include "ada.h"
#include "parser.h"

namespace ada {

  ada_warn_unused ada::url parse(std::string_view input, std::optional<ada::url> base_url, ada::encoding_type encoding) noexcept {
    auto parser = new url_parser(input, base_url, encoding, SCHEME_START);

    return parser->get_url();
  }

} // namespace ada
