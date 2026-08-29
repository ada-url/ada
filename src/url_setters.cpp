// Credential and hash setters. Own TU so Valgrind/CodSpeed I-cache for
// SetUsername / SetPassword / SetHash is not charged against the 700 KB
// unity parse object. Rollback is decided with a local helper: calling
// needs_rollback_snapshot() would jump back into ada.cpp.o at ~0x5500
// (that is why the previous isolation recovered only ~0.2 us).
// Amalgamation leaves ADA_URL_SETTERS_SEPARATE_TU unset and compiles
// these methods once via url_aggregator.cpp.
//
#include <cstring>
#include <string>
#include <string_view>

// ada.h pulls parser.h before url.h so ada::parser friends resolve.
// This TU is not part of the amalgamate include tree.
#include "ada.h"
#include "ada/log.h"
#include "ada/unicode-inl.h"
#include "url_setters-inl.h"
