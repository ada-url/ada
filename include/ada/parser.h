/**
 * @file parser.h
 * @brief Definitions for the parser.
 */
#ifndef ADA_PARSER_H
#define ADA_PARSER_H

#include "ada/state.h"
#include "ada/url.h"
#include "ada/encoding_type.h"
#include "ada/expected.h"
#include <optional>
#include <string_view>

/**
 * @namespace ada::parser
 * @brief Includes the definitions for supported parsers
 */
namespace ada::parser {

  /**
   * Parses a url.
   */
  url parse_url(std::string_view user_input,
                const ada::url* base_url = nullptr,
                ada::encoding_type encoding = ada::encoding_type::UTF8);

} // namespace ada

#endif // ADA_PARSER_H
