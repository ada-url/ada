/**
 * @file parser.h
 * @brief Definitions for the parser.
 */
#ifndef ADA_PARSER_H
#define ADA_PARSER_H

#include "state.h"
#include "url.h"
#include "encoding_type.h"

#include <optional>
#include <string_view>

namespace ada::parser {

  /**
   * Parses a url.
   */
  url parse_url(std::string_view user_input,
                std::optional<ada::url> base_url = std::nullopt,
                ada::encoding_type encoding = ada::encoding_type::UTF8,
                std::optional<ada::url> optional_url = std::nullopt);

} // namespace ada

#endif // ADA_PARSER_H
