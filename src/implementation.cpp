#include "implementation.h"

#include <string_view>

#include "common_defs.h"
#include "unicode.h"
#include "url.h"
#include "url_aggregator.h"
#include "url_base.h"
#include "url_pattern.h"

namespace ada {

template <class result_type>
ada_warn_unused tl::expected<result_type, errors> parse(
    std::string_view input, const result_type* base_url) {
  result_type u =
      ada::parser::parse_url_impl<result_type, true>(input, base_url);
  if (!u.is_valid) {
    return tl::unexpected(errors::type_error);
  }
  return u;
}

template ada::result<url> parse<url>(std::string_view input,
                                     const url* base_url = nullptr);
template ada::result<url_aggregator> parse<url_aggregator>(
    std::string_view input, const url_aggregator* base_url = nullptr);

std::string href_from_file(std::string_view input) {
  // This is going to be much faster than constructing a URL.
  std::string tmp_buffer;
  std::string_view internal_input;
  if (unicode::has_tabs_or_newline(input)) {
    tmp_buffer = input;
    helpers::remove_ascii_tab_or_newline(tmp_buffer);
    internal_input = tmp_buffer;
  } else {
    internal_input = input;
  }
  std::string path;
  if (internal_input.empty()) {
    path = "/";
  } else if ((internal_input[0] == '/') || (internal_input[0] == '\\')) {
    helpers::parse_prepared_path(internal_input.substr(1),
                                 ada::scheme::type::FILE, path);
  } else {
    helpers::parse_prepared_path(internal_input, ada::scheme::type::FILE, path);
  }
  return "file://" + path;
}

bool can_parse(std::string_view input, const std::string_view* base_input) {
  ada::url_aggregator base_aggregator;
  ada::url_aggregator* base_pointer = nullptr;

  if (base_input != nullptr) {
    base_aggregator = ada::parser::parse_url_impl<ada::url_aggregator, false>(
        *base_input, nullptr);
    if (!base_aggregator.is_valid) {
      return false;
    }
    base_pointer = &base_aggregator;
  }

  ada::url_aggregator result =
      ada::parser::parse_url_impl<ada::url_aggregator, false>(input,
                                                              base_pointer);
  return result.is_valid;
}

ada_warn_unused std::string to_string(ada::encoding_type type) {
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

ada_warn_unused tl::expected<url_pattern, errors> parse_url_pattern(
    std::variant<std::string_view, url_pattern_init> input,
    const std::string_view* base_url, const url_pattern_options* options) {
  return parser::parse_url_pattern_impl(std::move(input), base_url, options);
}

}  // namespace ada
