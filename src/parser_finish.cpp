// Cold simple-absolute finish helpers. Compiled as their own TU so the
// unity ada.cpp I-cache for setters is not displaced by userinfo / IPv6 /
// port / handoff. The anonymous-namespace scanners are compiled into this
// TU as well because the finish helpers call them. The amalgamated
// single-header build leaves ADA_PARSER_FINISH_SEPARATE_TU unset and
// compiles the full parser.cpp once via ada.cpp.
#define ADA_SKIP_PARSER_HOT
#include "parser.cpp"
