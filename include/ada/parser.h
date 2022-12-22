#ifndef ADA_PARSER_H
#define ADA_PARSER_H

#include "state.h"
#include "url.h"

#include <optional>
#include <string_view>

namespace ada::parser {

   std::optional<std::string_view> domain_to_ascii(const std::string_view input, bool be_strict = false);
   std::optional<std::string_view> parse_opaque_host(std::string_view input, bool validation_error);
   std::optional<std::string_view> parse_ipv6(std::string_view input);
   std::tuple<uint16_t, bool, bool> parse_ipv4_number(std::string_view input);
   std::optional<std::string_view> parse_host(std::string_view input, bool is_not_special, bool has_validation_error);

   url parse_url(std::string_view user_input,
                std::optional<ada::url> base_url,
                std::optional<ada::encoding_type> encoding_override,
                std::optional<ada::state> given_state_override);

} // namespace ada

#endif //ADA_PARSER_H
