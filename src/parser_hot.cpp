// Simple-absolute / relative fast path and ada::parse. Own TU so the
// SIMD scanners and try_parse do not displace setter I-cache in the
// unity ada.cpp. parse_url_impl stays in ada.cpp (always_inline helpers).
#define ADA_SKIP_PARSER_FINISH
#define ADA_SKIP_PARSER_IMPL
#include "parser.cpp"
