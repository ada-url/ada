#include "ada.h"
#include "checkers.cpp"
#include "unicode.cpp"
#if !defined(ADA_PERCENT_ENCODE_SIMD_SEPARATE_TU)
#include "unicode_percent_encode.cpp"
#endif
#if !defined(ADA_PARSER_HOST_SCAN_SEPARATE_TU)
#include "parser_host_scan.cpp"
#endif
#include "serializers.cpp"
#include "implementation.cpp"
#include "helpers.cpp"
#include "url.cpp"
#include "parser.cpp"
#include "url_components.cpp"
#include "url_aggregator.cpp"

#if ADA_INCLUDE_URL_PATTERN
#include "url_pattern.cpp"
#include "url_pattern_helpers.cpp"
#include "url_pattern_regex.cpp"
#endif  // ADA_INCLUDE_URL_PATTERN

#include "ada_c.cpp"
