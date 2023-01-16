#ifndef ADA_PARSER_H
#define ADA_PARSER_H

#include "state.h"
#include "url.h"
#include "encoding_type.h"

#include <optional>
#include <string_view>

namespace ada::parser {
  // first_percent should be  = plain.find('%')
  std::optional<std::string> to_ascii(std::string_view plain, bool be_strict, size_t first_percent);

  bool parse_opaque_host(std::optional<std::string>& out, std::string_view input);
  bool parse_ipv6(std::optional<std::string>& out, std::string_view input);
  bool parse_ipv4(std::optional<std::string>& out, std::string_view input);
  bool parse_host(std::optional<std::string>& out, std::string_view input, bool is_not_special, bool input_is_ascii);

  url parse_url(std::string_view user_input,
                std::optional<ada::url> base_url = std::nullopt,
                ada::encoding_type encoding = ada::encoding_type::UTF8,
                std::optional<ada::url> optional_url = std::nullopt,
                std::optional<ada::state> state_override = std::nullopt);

} // namespace ada

#endif // ADA_PARSER_H
