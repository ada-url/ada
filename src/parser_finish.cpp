// Cold simple-absolute finish helpers and relative resolution. Own TU so
// the unity ada.cpp I-cache for setters and the absolute fast-path I-cache
// are not displaced by userinfo / IPv6 / port / handoff / relative.
// Scanners are compiled here because the finish helpers call them.
// Amalgamation leaves ADA_PARSER_FINISH_SEPARATE_TU unset and compiles
// the full parser.cpp once via ada.cpp.
#define ADA_SKIP_PARSER_FASTPATH
#define ADA_SKIP_PARSER_IMPL
// Relative resolution lives here with the other non-absolute helpers.
#include "parser.cpp"
