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
  std::optional<std::string_view> parse_opaque_host(std::string_view input);
  std::optional<std::string_view> parse_ipv6(std::string_view input);
  std::optional<std::string_view> parse_host(std::string_view input, bool is_not_special);

  url parse_url(std::string_view user_input,
                std::optional<ada::url> base_url,
                std::optional<ada::encoding_type> encoding_override,
                std::optional<ada::state> given_state_override);

} // namespace ada

#endif //ADA_PARSER_H
