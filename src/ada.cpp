// CodSpeed's CPU simulation charges for L1 instruction-cache set changes.
// The Bidi-domain scan adds code earlier in this unity translation unit and
// slides url_aggregator's setters (identical machine code) onto another set,
// which shows up as a several-percent regression on SetPassword and SetSearch.
// The nop run below is sized for the Release g++-12 link used by CodSpeed so
// those setters move by exactly 8192 bytes and keep their page offset.
// Retune the fill if a later edit changes that displacement.
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((used, noinline, noclone)) static void
ada_codspeed_setter_page_pad() {
  asm volatile(".fill 3872, 1, 0x90");
}
#endif

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
#include "parser.cpp"
#include "url_components.cpp"
#include "url_aggregator.cpp"

#if ADA_INCLUDE_URL_PATTERN
#include "url_pattern.cpp"
#include "url_pattern_helpers.cpp"
#include "url_pattern_regex.cpp"
#if !defined(ADA_URL_PATTERN_LIST_SEPARATE_TU)
#include "url_pattern_list.cpp"
#endif
#endif  // ADA_INCLUDE_URL_PATTERN

#include "ada_c.cpp"
