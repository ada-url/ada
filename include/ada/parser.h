#ifndef ADA_PARSER_H
#define ADA_PARSER_H

#include "state.h"
#include "url.h"

#include <optional>
#include <string_view>

namespace ada::parser {
  // first_percent should be  = plain.find('%')
  std::optional<std::string> to_ascii(std::string_view plain, bool be_strict, size_t first_percent);

  std::optional<ada::url_host> parse_opaque_host(std::string_view input);
  std::optional<ada::url_host> parse_ipv6(std::string_view input);
  std::optional<ada::url_host> parse_host(std::string_view input, bool is_not_special, bool input_is_ascii);

  url parse_url(std::string user_input,
                std::optional<ada::url> base_url = std::nullopt,
                ada::encoding_type encoding = UTF8,
                std::optional<ada::url> optional_url = std::nullopt,
                std::optional<ada::state> state_override = std::nullopt);

} // namespace ada

#endif // ADA_PARSER_H
