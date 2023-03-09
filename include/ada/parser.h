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
#include "ada/url_aggregator.h"
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
  template <class result_type = ada::url>
  result_type parse_url(std::string_view user_input,
                        const ada::url* base_url = nullptr,
                        ada::encoding_type encoding = ada::encoding_type::UTF8);

  extern template url_aggregator parse_url<url_aggregator>(std::string_view user_input,
                                                           const ada::url* base_url,
                                                           ada::encoding_type encoding);

  extern template url parse_url<url>(std::string_view user_input,
                                     const ada::url* base_url,
                                     ada::encoding_type encoding);

} // namespace ada

#endif // ADA_PARSER_H
