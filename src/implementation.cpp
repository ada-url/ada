#include "ada.h"

namespace ada {

  ada_warn_unused url parse(std::string_view input,
                            std::optional<ada::url> base_url,
                            ada::encoding_type encoding) noexcept {

    return ada::parser::parse_url(input, std::move(base_url), encoding, std::nullopt);
  }

} // namespace ada
