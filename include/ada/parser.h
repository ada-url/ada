#ifndef ADA_PARSER_H
#define ADA_PARSER_H

#include "state.h"
#include "url.h"

#include <optional>
#include <string_view>

namespace ada::parser {

  // Return `std::nullopt` if the parser result is failure.

  bool domain_to_ascii(std::string_view input);
  std::optional<uint16_t> parse_ipv4_number(std::string_view input);
  std::optional<std::string> parse_opaque_host(std::string_view input);
  std::optional<std::string> parse_ipv6(std::string_view input);
  std::optional<std::string> parse_host(std::string_view input, bool is_not_special);

  url parse_url(std::string user_input,
                std::optional<ada::url> base_url,
                ada::encoding_type encoding = UTF8,
                std::optional<ada::state> state_override = std::nullopt);

} // namespace ada

#endif //ADA_PARSER_H
