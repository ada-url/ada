#ifndef ADA_H
#define ADA_H

// To enable logging, set ADA_LOGGING to 1:
#ifndef ADA_LOGGING
#define ADA_LOGGING 1
#endif


#ifndef ADA_DEVELOP_MODE
#define ADA_DEVELOP_MODE 1 /* Should be set to 0 in a release. */
#endif


#include "ada/character_sets.h"
#include "ada/checkers.h"
#include "ada/common_defs.h"
#include "ada/encoding_type.h"
#include "ada/helpers.h"
#include "ada/parser.h"
#include "ada/scheme.h"
#include "ada/serializers.h"
#include "ada/state.h"
#include "ada/unicode.h"
#include "ada/url.h"

// Public API
#include "ada/ada_version.h"
#include "ada/implementation.h"

#endif // ADA_H
