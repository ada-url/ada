#ifndef ADA_PARSER_HOST_SCAN_H
#define ADA_PARSER_HOST_SCAN_H

#include <cstddef>
#include <cstdint>

namespace ada::parser {

// Remainder of scan_plain_host after SIMD windows. Own TU so the ada.cpp
// unity inlining budget for setters shrinks vs a scalar loop in parser.cpp
// (same split as percent_encode).
bool scan_plain_host_tail(const uint8_t* b, size_t start, size_t len,
                          size_t& end, bool& has_upper, bool& has_x) noexcept;

}  // namespace ada::parser

#endif  // ADA_PARSER_HOST_SCAN_H
