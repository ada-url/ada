#ifndef ADA_H
#define ADA_H


#ifndef ADA_DEVELOP_MODE
#define ADA_DEVELOP_MODE 1 /* Should be set to 0 in a release. */
#endif


#include "ada/character_sets.h"
#include "ada/checkers.h"
#include "ada/common_defs.h"
#include "ada/log.h"
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
