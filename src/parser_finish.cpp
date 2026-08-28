// Cold simple-absolute finish helpers. Own TU so the unity ada.cpp
// I-cache for setters is not displaced by userinfo / IPv6 / port / handoff.
// Scanners are compiled here because the finish helpers call them.
// Amalgamation leaves ADA_PARSER_FINISH_SEPARATE_TU unset and compiles
// the full parser.cpp once via ada.cpp.
#define ADA_SKIP_PARSER_FASTPATH
#define ADA_SKIP_PARSER_IMPL
#include "parser.cpp"
