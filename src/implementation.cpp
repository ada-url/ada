#include <string_view>

#include "ada.h"
#include "ada/common_defs.h"
#include "ada/parser.h"
#include "ada/url.h"
#include "ada/url_aggregator.h"

namespace ada {

template <class result_type>
ada_warn_unused tl::expected<result_type, ada::errors> parse(
    std::string_view const input, const result_type* base_url) {
  result_type u = ada::parser::parse_url<result_type>(input, base_url);
  if (!u.is_valid) {
    return tl::unexpected(errors::generic_error);
  }
  return u;
}

template ada::result<url> parse<url>(std::string_view input,
                                     const url* base_url);
template ada::result<url_aggregator> parse<url_aggregator>(
    std::string_view input, const url_aggregator* base_url);

std::string href_from_file(std::string_view const path) {
  // This is going to be much faster than constructing a URL.
  std::string tmp_buffer;
  std::string_view internal_input;
  if (unicode::has_tabs_or_newline(path)) {
    tmp_buffer = path;
    helpers::remove_ascii_tab_or_newline(tmp_buffer);
    internal_input = tmp_buffer;
  } else {
    internal_input = path;
  }
  std::string file_path;
  if (internal_input.empty()) {
    file_path = "/";
  } else if ((internal_input[0] == '/') || (internal_input[0] == '\\')) {
    helpers::parse_prepared_path(internal_input.substr(1),
                                 ada::scheme::type::FILE, file_path);
  } else {
    helpers::parse_prepared_path(internal_input, ada::scheme::type::FILE,
                                 file_path);
  }
  return "file://" + file_path;
}

bool can_parse(std::string_view const input,
               const std::string_view* base_input) {
  ada::result<ada::url_aggregator> base;
  ada::url_aggregator* base_pointer = nullptr;
  if (base_input != nullptr) {
    base = ada::parse<url_aggregator>(*base_input);
    if (!base) {
      return false;
    }
    base_pointer = &base.value();
  }
  return ada::parse<url_aggregator>(input, base_pointer).has_value();
}

ada_warn_unused std::string to_string(ada::encoding_type const type) {
  switch (type) {
    case ada::encoding_type::UTF8:
      return "UTF-8";
    case ada::encoding_type::UTF_16LE:
      return "UTF-16LE";
    case ada::encoding_type::UTF_16BE:
      return "UTF-16BE";
    default:
      unreachable();
  }
}

}  // namespace ada
