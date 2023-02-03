#include <string_view>

#include "ada.h"
#include "ada/common_defs.h"
#include "ada/parser.h"
#include "ada/url.h"

namespace ada {

  ada_warn_unused tl::expected<ada::url,ada::errors> parse(std::string_view input,
                            const ada::url* base_url,
                            ada::encoding_type encoding) {
    if(encoding != encoding_type::UTF8) {
      // @todo Add support for non UTF8 input
    }
    ada::url u = ada::parser::parse_url(input, base_url, encoding);
    if(!u.is_valid) { return tl::unexpected(errors::generic_error); }
    return u;
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
