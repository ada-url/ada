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

  std::string href_from_file(std::string_view input) {
    // This is going to be much faster than constructing a URL.
    std::string tmp_buffer;
    std::string_view internal_input;
    if(unicode::has_tabs_or_newline(input)) {
      tmp_buffer = input;
      helpers::remove_ascii_tab_or_newline(tmp_buffer);
      internal_input = tmp_buffer;
    } else {
      internal_input = input;
    }
    std::string path;
    if(internal_input.empty()) {
      path = "/";
    } else if((internal_input[0] == '/') ||(internal_input[0] == '\\')){
      helpers::parse_prepared_path(internal_input.substr(1), ada::scheme::type::FILE, path);
    } else {
      helpers::parse_prepared_path(internal_input, ada::scheme::type::FILE, path);
    }
    return "file://" + path;
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
