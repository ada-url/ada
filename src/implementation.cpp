#include <string_view>
#include <utility>

#include "ada.h"
#include "ada/common_defs.h"
#include "ada/parser.h"
#include "ada/url.h"

namespace ada {

  ada_warn_unused url parse(std::string_view input,
                            std::optional<ada::url> base_url,
                            ada::encoding_type encoding) {
    if(encoding != encoding_type::UTF8) {
      // @todo Add support for non UTF8 input
    }
    // @todo std::move(base_url) might be unwise. Check.
    return ada::parser::parse_url(input, std::move(base_url), encoding);
  }

  ada_warn_unused std::string to_string(ada::encoding_type type) {
    switch(type) {
    case ada::encoding_type::UTF8 : return "UTF-8";
    case ada::encoding_type::UTF_16LE : return "UTF-16LE";
    case ada::encoding_type::UTF_16BE : return "UTF-16BE";
    default: unreachable();
    }
  }

} // namespace ada
