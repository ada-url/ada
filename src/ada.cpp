#include "ada.h"
#include "checkers.cpp"
#include "unicode.cpp"
#if !defined(ADA_PERCENT_ENCODE_SIMD_SEPARATE_TU)
#include "unicode_percent_encode.cpp"
#endif
#include "serializers.cpp"
#include "implementation.cpp"
#include "helpers.cpp"
#include "url.cpp"
#if defined(ADA_PARSER_FINISH_SEPARATE_TU)
#define ADA_SKIP_PARSER_FINISH
#define ADA_SKIP_PARSER_FASTPATH
#endif
#include "parser.cpp"
#include "url_components.cpp"
#include "url_aggregator.cpp"

#if ADA_INCLUDE_URL_PATTERN
#include "url_pattern.cpp"
#include "url_pattern_helpers.cpp"
#include "url_pattern_regex.cpp"
#endif  // ADA_INCLUDE_URL_PATTERN

#include "ada_c.cpp"
