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
#include "ada/href_aggregator.h"
#include <optional>
#include <string_view>

/**
 * @namespace ada::parser
 * @brief Includes the definitions for supported parsers
 */
namespace ada::parser {

  // TODO: parse_url should not take a onst ada::url* base_url, instead it should take
  // in a pointer to a more abstract class that can provide the basis for what we need.

  /**
   * Parses a url.
   */
  template <class result_type = url>
  result_type parse_url(std::string_view user_input,
                const ada::url* base_url = nullptr,
                ada::encoding_type encoding = ada::encoding_type::UTF8);

  extern template href_aggregator parse_url<href_aggregator>(std::string_view user_input,
                const ada::url* base_url = nullptr,
                ada::encoding_type encoding = ada::encoding_type::UTF8);
  extern template url parse_url<url>(std::string_view user_input,
                const ada::url* base_url = nullptr,
                ada::encoding_type encoding = ada::encoding_type::UTF8);

} // namespace ada

#endif // ADA_PARSER_H
