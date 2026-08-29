/**
 * @file url_pattern_list_compiler.h
 * @brief The url_pattern_list route-set compiler: pattern classification and
 * the build-time table construction behind ada::parse_url_pattern_list.
 *
 * This header is NOT part of the public API and is not included from ada.h:
 * only src/url_pattern_list.cpp (and, through the amalgamated ada.cpp, the
 * url_pattern_list fuzzer) include it. The matcher-visible table layout it
 * produces is declared in include/ada/url_pattern_list.h.
 */
#ifndef ADA_URL_PATTERN_LIST_COMPILER_H
#define ADA_URL_PATTERN_LIST_COMPILER_H

#include "ada/common_defs.h"
#include "ada/url_pattern.h"
#include "ada/url_pattern_list.h"

#include <cstdint>
#include <string>
#include <vector>

#if ADA_INCLUDE_URL_PATTERN
namespace ada::url_pattern_list_compiler {

/**
 * Maximum number of entries a perfect-hash dispatch table may index (slot
 * ordinals are 8-bit, with 0xFF reserved for "empty"). Nodes with a larger
 * static fanout are demoted to a linear scan: slower, never incorrect.
 */
inline constexpr uint32_t max_dispatch_table_entries = 254;

/**
 * Static fanout up to which a node compares its children directly, in
 * turn; wider nodes dispatch through a projection table. Segment keys are
 * short and each compare is gated by the key length, so direct compares
 * measure faster than a projection up to 16 children (16 vs 8: static hits
 * 25.9 vs 28.0 ns/url, param hits 32.3 vs 35.5 on the PR benchmark).
 */
inline constexpr uint32_t max_direct_children = 16;

/**
 * The kind of one compiled pattern segment. The numeric values define match
 * priority: at the first differing segment, a literal beats a ":param" and a
 * ":param" beats a "*" (find-my-way / Express-compatible specificity order).
 */
enum class segment_kind : uint8_t {
  literal = 0,
  param = 1,
  wildcard = 2,
};

/**
 * One '/'-separated segment of a compiled pattern: a literal text (already
 * canonicalized by the URLPattern pattern parser), a ":param" (text = group
 * name), or a trailing "*" wildcard.
 */
struct route_segment {
  segment_kind kind = segment_kind::literal;
  std::string text{};
};

/**
 * Everything the compiler knows about one route. `kind_sequence` packs the
 * per-segment kinds two bits per segment, most significant first, so that
 * comparing (kind_sequence, kind_length, route index) as a tuple is exactly
 * the documented specificity order. For regexp-mode routes, `segments`
 * holds only the anchored literal prefix (the leading segments that are
 * whole fixed text, closed by a '/'), which the auxiliary-route pruning
 * uses to rule out routes that can never match the same input.
 */
struct route_info {
  std::vector<route_segment> segments{};
  // Capture group names, in capture order (params left to right, then the
  // wildcard group). Regexp-mode routes: filled from the compiled component.
  std::vector<std::string> group_names{};
  uint64_t kind_sequence = 0;
  uint8_t kind_length = 0;
  url_pattern_list_detail::route_mode mode =
      url_pattern_list_detail::route_mode::sequential;
  bool has_wildcard = false;
  bool all_literal = false;
};

/**
 * Classifies a URLPattern part list into '/'-separated pattern segments.
 * Returns true when the pattern is expressible in the static/":param"/"*"
 * subset (every segment wholly a literal, a param, or a final wildcard);
 * `segments` and `group_names` are only valid on success.
 */
bool classify_parts(const std::vector<url_pattern_part>& parts,
                    std::vector<route_segment>& segments,
                    std::vector<std::string>& group_names);

/**
 * Computes kind sequence and flags from route.segments and decides the
 * route's mode: trie when every fast-path build limit is met, sequential
 * otherwise (the empty pattern, more than max_trie_pattern_segments
 * segments, or more than max_captures_per_route capture groups).
 */
void finalize_route(route_info& route) noexcept;

/**
 * Best-effort kind sequence for a route that needs regexp matching, so it can
 * participate in the specificity order: custom "(...)" groups count as params,
 * full wildcards and modified ("?", "+", "*") groups terminate the sequence as
 * a wildcard tail. This mapping is an approximation and is called out as an
 * open question in the class documentation. Also records the route's
 * anchored literal prefix in route.segments and sets mode = regexp.
 */
void approximate_kind_sequence(const std::vector<url_pattern_part>& parts,
                               route_info& route);

/**
 * True when route `a` (at insertion index `a_index`) outranks route `b`.
 */
constexpr bool route_outranks(const route_info& a, size_t a_index,
                              const route_info& b, size_t b_index) noexcept {
  return url_pattern_list_detail::outranks(a.kind_sequence, a.kind_length,
                                           a_index, b.kind_sequence,
                                           b.kind_length, b_index);
}

/**
 * Compiles the route set: builds the trie and its dispatch plans over the
 * trie-mode routes, the segment table, the auxiliary-route table with its
 * per-route challenger ranges, and packs everything into one arena. Never
 * fails: any node whose offline search fails is demoted to a slower but
 * correct plan.
 * Literal texts are used as given (the caller has already case-folded them
 * when ignore_case is set).
 */
url_pattern_list_detail::compiled_routes compile_route_set(
    std::vector<route_info>& routes);

}  // namespace ada::url_pattern_list_compiler
#endif  // ADA_INCLUDE_URL_PATTERN
#endif  // ADA_URL_PATTERN_LIST_COMPILER_H
