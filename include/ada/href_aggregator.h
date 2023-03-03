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
 *
 * The href_aggregator contains a single string (buffer) along with a
 * set of offsets (components). That is sufficient to qualified as a fully
 * parsed URL. However, unlike ada/url, updates can be more difficult because
 * the components are not separate. However, we should be able to map an
 * ada/href_aggregator to an ada/url quickly and efficiently.
 *
 * In effect, we can view ada/url and ada/href_aggregator as equivalent.
 * The ada/href_aggregator class is smaller and faster when processing essentially
 * immutable URLs. The ada/url class is larger and has more overhead, but it would
 * be well suited for URLs that are built by parts and modified. For many temporary
 * or ephemeral instances, an href_aggregator would be more performant.
 *
 * TODO: both ada/url and ada/href_aggregator should have a common interface, 
 * and it is an instance where using inheritance might be ease programming.
 */
struct href_aggregator {
  bool is_valid;
  url_components components;
  ada::scheme::type type{ada::scheme::type::NOT_SPECIAL};

  ada_really_inline bool is_special() const noexcept {
    return type != ada::scheme::NOT_SPECIAL;
  }

  /**
   * Put the specified value as the fragment of this URL.
   * Should be called last.
   */
  ada_really_inline void set_fragment(std::string_view p) {
    //TODO: update components
    buffer += p;
  }

  ada_really_inline bool parse_scheme(const std::string_view input) {
    auto parsed_type = ada::scheme::get_scheme_type(input);
    bool is_input_special = (parsed_type != ada::scheme::NOT_SPECIAL);
    if (is_input_special) { // fast path!!!
      type = parsed_type;
      buffer += input;
      //TODO: update components
    } else { // slow path
      std::string _buffer = std::string(input);
      unicode::to_lower_ascii(_buffer.data(), _buffer.size());
      type = ada::scheme::get_scheme_type(_buffer);
      buffer += _buffer;
      //TODO: update components
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
