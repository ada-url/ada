/**
 * @file href_aggreator.h
 * @brief Definitions for the href_aggregator.
 */
#ifndef ADA_HREF_AGGREGATOR_H
#define ADA_HREF_AGGREGATOR_H

#include "ada/encoding_type.h"
#include "ada/expected.h"
#include <optional>
#include <string_view>

/**
 * @namespace ada::parser
 * @brief Code for href_aggregator
 */
namespace ada::parser {
/**
 * Sometimes, you do not want to construct a full URL structure and you would
 * be satisfied with just a normalized href string.
 */
struct href_aggregator {
  bool is_valid;
  ada::scheme::type type{ada::scheme::type::NOT_SPECIAL};

  ada_really_inline bool is_special() const noexcept {
    return type != ada::scheme::NOT_SPECIAL;
  }

  /**
   * Put the specified value as the fragment of this URL.
   * Should be called last.
   */
  ada_really_inline void set_fragment(std::string_view p) { buffer += p; }

  ada_really_inline bool parse_scheme(const std::string_view input) {
    auto parsed_type = ada::scheme::get_scheme_type(input);
    bool is_input_special = (parsed_type != ada::scheme::NOT_SPECIAL);
    if (is_input_special) { // fast path!!!
      type = parsed_type;
      buffer += input;
    } else { // slow path
      std::string _buffer = std::string(input);
      unicode::to_lower_ascii(_buffer.data(), _buffer.size());
      type = ada::scheme::get_scheme_type(_buffer);
      buffer += _buffer;
    }
    return true;
  }

  ada_really_inline ada::scheme::type get_scheme_type() const noexcept {
    return type;
  }

  std::string buffer;
};
} // namespace ada::parser
#endif // ADA_HREF_AGGREGATOR_H