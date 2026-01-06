/**
 * @file ada.h
 * @brief Main header for the Ada URL parser library.
 *
 * This is the primary entry point for the Ada URL parser library. Including
 * this single header provides access to the complete Ada API, including:
 *
 * - URL parsing via `ada::parse()` function
 * - Two URL representations: `ada::url` and `ada::url_aggregator`
 * - URL search parameters via `ada::url_search_params`
 * - URL pattern matching via `ada::url_pattern` (URLPattern API)
 * - IDNA (Internationalized Domain Names) support
 *
 * @example
 * ```cpp
 * #include "ada.h"
 *
 * // Parse a URL
 * auto url = ada::parse("https://example.com/path?query=1");
 * if (url) {
 *     std::cout << url->get_hostname(); // "example.com"
 * }
 * ```
 *
 * @see https://url.spec.whatwg.org/ - WHATWG URL Standard
 * @see https://github.com/ada-url/ada - Ada URL Parser GitHub Repository
 */
#ifndef ADA_H
#define ADA_H

#include "ada/ada_idna.h"
#include "ada/character_sets.h"
#include "ada/character_sets-inl.h"
#include "ada/checkers-inl.h"
#include "ada/common_defs.h"
#include "ada/log.h"
#include "ada/encoding_type.h"
#include "ada/helpers.h"
#include "ada/parser.h"
#include "ada/parser-inl.h"
#include "ada/scheme.h"
#include "ada/scheme-inl.h"
#include "ada/serializers.h"
#include "ada/state.h"
#include "ada/unicode.h"
#include "ada/url_base.h"
#include "ada/url_base-inl.h"
#include "ada/url-inl.h"
#include "ada/url_components.h"
#include "ada/url_components-inl.h"
#include "ada/url_aggregator.h"
#include "ada/url_aggregator-inl.h"
#include "ada/url_search_params.h"
#include "ada/url_search_params-inl.h"

#include "ada/url_pattern.h"
#include "ada/url_pattern-inl.h"
#include "ada/url_pattern_helpers.h"
#include "ada/url_pattern_helpers-inl.h"
#include "ada/url_pattern_regex.h"

// Public API
#include "ada/ada_version.h"
#include "ada/implementation.h"
#include "ada/implementation-inl.h"

#endif  // ADA_H
