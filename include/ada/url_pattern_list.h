/**
 * @file url_pattern_list.h
 * @brief Compiled set-level matching over URLPattern pathname patterns.
 *
 * `ada::url_pattern_list` answers the question "which of my N routes matches
 * this pathname, and what are the parameter values?" in a single probe
 * structure instead of a loop of N `url_pattern::exec` calls. The whole route
 * set is compiled once, at construction, into a segment trie with per-node
 * witness-byte dispatch tables, a whole-pathname exact table for fully static
 * routes, and per-shape dispatch tables for parameterized routes. Matching a
 * pathname against the compiled set is allocation-free and does not execute
 * any regular expression for routes written in the common
 * static / ":param" / "*" subset.
 *
 * This implements the route-set ("URLPatternList") use case discussed in
 * https://github.com/whatwg/urlpattern/issues/166 for the pathname component.
 *
 * Correctness does not depend on the fast path: inputs or routes that exceed
 * the fast-path limits (documented on the constants in
 * `ada::url_pattern_list_helpers`) are matched by a sequential fallback with
 * identical priority semantics, never rejected and never answered wrongly.
 *
 * @see https://urlpattern.spec.whatwg.org/
 */
#ifndef ADA_URL_PATTERN_LIST_H
#define ADA_URL_PATTERN_LIST_H

#include "ada/common_defs.h"
#include "ada/errors.h"
#include "ada/expected.h"
#include "ada/url_pattern.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#if ADA_INCLUDE_URL_PATTERN
namespace ada {

/**
 * Internal machinery for ada::url_pattern_list: the provider-independent
 * route-set compiler and matcher. Nothing in this namespace is part of the
 * supported public API except the limit constants and the `capture` struct
 * (re-exported by url_pattern_list_match_result), which are documented
 * because they delimit the fast path and the result contract. Everything
 * else lives here only because the url_pattern_list class template needs it
 * and is marked @private; it may change at any time.
 * @namespace ada::url_pattern_list_helpers
 */
namespace url_pattern_list_helpers {

/**
 * Maximum number of captures (":param" groups plus one trailing "*" group)
 * a route may declare and still be compiled into the fast path. Routes with
 * more groups are matched by the sequential fallback; their match is still
 * correct, but only the first `max_captures_per_route` captures are reported
 * (see url_pattern_list_match_result::captures_truncated).
 */
inline constexpr uint32_t max_captures_per_route = 8;

/**
 * Maximum number of '/'-separated segments an input pathname may have and
 * still be matched by the fast path. Longer inputs fall back to the
 * sequential matcher and are still matched correctly.
 */
inline constexpr uint32_t max_fast_path_segments = 24;

/**
 * Maximum input pathname length (bytes) accepted by the fast path; segment
 * offsets are tracked in 16-bit integers internally. Longer inputs fall back
 * to the sequential matcher and are still matched correctly.
 */
inline constexpr uint32_t max_fast_path_pathname_length = 4096;

/**
 * Maximum number of pattern segments a route may have and still be compiled
 * into the trie fast path. Deeper routes are matched by the sequential
 * fallback with identical semantics.
 */
inline constexpr uint32_t max_trie_pattern_segments = 16;

/**
 * Maximum number of entries any perfect-hash dispatch table may index (slot
 * ordinals are 8-bit, with 0xFF reserved for "empty"). Nodes with a larger
 * static fanout, and shape groups with more entries, are demoted to a linear
 * scan: slower, never incorrect.
 */
inline constexpr uint32_t max_dispatch_table_entries = 254;

/**
 * @private
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
 * @private
 * One '/'-separated segment of a compiled pattern: a literal text (already
 * canonicalized by the URLPattern pattern parser), a ":param" (text = group
 * name), or a trailing "*" wildcard.
 */
struct route_segment {
  segment_kind kind = segment_kind::literal;
  std::string text{};
};

/** @private How one route of the set is matched. */
enum class route_mode : uint8_t {
  // Compiled into the trie / exact-table / shape-table fast path.
  trie,
  // Safe static/":param"/"*" syntax, but beyond a fast-path build limit
  // (segment depth, capture count, empty literal segment): matched by the
  // sequential segment matcher.
  sequential,
  // The pattern needs URLPattern regexp semantics (custom "(...)" groups,
  // "?"/"+"/"*" modifiers, non-segment-aligned groups): matched through the
  // regex provider via ada's url_pattern_component.
  regexp,
};

/**
 * @private
 * Everything the matcher knows about one route. `kind_sequence` packs the
 * per-segment kinds two bits per segment, most significant first, so that
 * comparing (kind_sequence, kind_length, route index) as a tuple is exactly
 * the documented specificity order.
 */
struct route_info {
  std::vector<route_segment> segments{};
  // Capture group names, in capture order (params left to right, then the
  // wildcard group). For regexp-mode routes: the component's name list.
  std::vector<std::string> group_names{};
  uint64_t kind_sequence = 0;
  // Index into the owning list's regexp component storage, or -1.
  int32_t regexp_component = -1;
  uint8_t kind_length = 0;
  route_mode mode = route_mode::sequential;
  bool has_wildcard = false;
  bool all_literal = false;
  // Set by compile_route_set: this route's answer is fully covered by the
  // whole-pathname exact table, so the fast path never needs to test it
  // sequentially.
  bool covered_by_static_table = false;
};

/** One capture: an (offset, length) slice of the matched pathname. */
struct capture {
  uint32_t offset = 0;
  uint32_t length = 0;
};

// ---- compiled tables -------------------------------------------------------
// The flat tables the matcher walks. All layout decisions (dispatch plans,
// perfect multipliers, probe orders) are made at build time by
// compile_route_set; the matcher only follows them.

/** @private One trie node; static children occupy a contiguous block of
 * edges. */
struct trie_node {
  // Perfect multiplier for projection dispatch (dispatch == 2).
  uint64_t multiplier = 0;
  int32_t first_child = 0;
  uint32_t slot_base = 0;
  // Child node index, ~route (pure-leaf shortcut), or -1.
  int32_t param_child = -1;
  // Route index of a "*" ending at this prefix, or -1.
  int32_t wild_route = -1;
  // Route ending exactly here, or -1.
  int32_t terminal_route = -1;
  uint16_t n_static = 0;
  // Witness plan: 3 nibble ids | count << 12 | use_len << 14.
  uint16_t witness_plan = 0;
  // 0 none, 1 direct (<=2 children), 2 projection, 3 linear scan.
  uint8_t dispatch = 0;
  // Slot table size == 1 << slot_bits.
  uint8_t slot_bits = 0;
  // 1 if the node still has a param/wildcard alternative to backtrack to.
  uint8_t has_alternative = 0;
};

/** @private One static edge; keys <= 16 bytes verify from the packed
 * windows alone. */
struct trie_edge {
  // Key bytes [0, min(8, len)), little-endian, zero-padded.
  uint64_t prefix = 0;
  // Key bytes [max(0, len - 8), len), little-endian, zero-padded.
  uint64_t suffix = 0;
  // Child node index; negative values encode ~route pure-leaf shortcuts.
  int32_t node = -1;
  // Full key in the blob (needed only when key_len > 16).
  uint32_t key_offset = 0;
  uint16_t key_length = 0;
};

/** @private Per-route capture positions, precomputed for trie-mode
 * routes. */
struct route_meta {
  uint8_t n_segments = 0;
  uint8_t n_params = 0;
  uint8_t wild = 0;
  // Ascending segment indices of the ":param" segments.
  std::array<uint8_t, max_captures_per_route> param_positions{};
};

/** @private One entry of the whole-pathname exact table or of a shape
 * group. */
struct static_entry {
  // Key text in the blob.
  uint32_t offset = 0;
  int32_t route = 0;
  uint16_t length = 0;
};

/**
 * @private
 * One (segment count, param-position mask) group of parameterized routes.
 * The probe gathers four witness bytes at precomputed segment positions,
 * multiplies, loads one slot, and verifies the static runs of the entry.
 */
struct shape_group {
  uint64_t multiplier = 0;
  // Bit s set <=> segment s is a ":param".
  uint32_t mask = 0;
  uint32_t slot_base = 0;
  uint32_t entry_base = 0;
  uint16_t n_entries = 0;
  uint8_t n_segments = 0;
  uint8_t slot_bits = 0;
  // 1 direct (verify entries in turn), 2 projection, 3 linear demotion.
  uint8_t dispatch = 0;
  uint8_t n_static = 0;
  uint8_t n_params = 0;
  // Maximal runs of consecutive static positions.
  uint8_t n_runs = 0;
  // Witness ids: (static ordinal << 5) | alphabet id (16 = length).
  std::array<uint8_t, 4> witness_ids{};
  // Absolute segment position of each witness.
  std::array<uint8_t, 4> witness_positions{};
  // Alphabet id of each witness.
  std::array<uint8_t, 4> witness_sub_ids{};
  std::array<uint8_t, max_captures_per_route + 1> run_first{};
  std::array<uint8_t, max_captures_per_route + 1> run_last{};
  // Segment positions of the params, ascending.
  std::array<uint8_t, max_captures_per_route> param_positions{};
};

/** @private Per input segment count: the shape groups probed, in
 * certified order. */
struct shape_directory_entry {
  uint32_t first = 0;
  uint32_t count = 0;
};

/** @private The compiled route set: every table the fast-path matcher
 * reads. */
struct compiled_routes {
  std::vector<trie_node> nodes{};
  std::vector<trie_edge> edges{};
  std::vector<uint8_t> slots{};
  std::vector<char> blob{};
  std::vector<route_meta> routes{};
  // Whole-pathname exact table over the fully static routes. A hit is the
  // final fast-path answer among compiled routes: a full static match has
  // the lexicographically minimal kind sequence.
  std::vector<uint8_t> static_slots{};
  std::vector<static_entry> static_entries{};
  uint64_t static_multiplier = 0;
  uint16_t static_witness_plan = 0;
  uint8_t static_slot_bits = 0;
  uint8_t has_static_table = 0;
  // Shape tables: whole-route witness dispatch for parameterized routes.
  std::vector<shape_group> groups{};
  std::vector<shape_directory_entry> group_directory{};
  std::vector<uint8_t> group_slots{};
  std::vector<static_entry> group_entries{};
  uint8_t has_shape_tables = 0;
};

/** @private Result of the fast-path engine or of the sequential route
 * matcher. */
struct engine_result {
  int32_t route = -1;
  uint32_t capture_count = 0;
  // False when the input exceeded a fast-path limit and the caller must run
  // the sequential fallback over the whole route set.
  bool within_fast_path = true;
  bool captures_truncated = false;
  std::array<capture, max_captures_per_route> captures{};
};

/**
 * @private
 * Classifies a URLPattern part list into '/'-separated pattern segments.
 * Returns true when the pattern is expressible in the static/":param"/"*"
 * subset (every segment wholly a literal, a param, or a final wildcard);
 * `segments` and `group_names` are only valid on success.
 */
bool classify_parts(const std::vector<url_pattern_part>& parts,
                    std::vector<route_segment>& segments,
                    std::vector<std::string>& group_names);

/**
 * @private
 * Computes kind sequence and flags from route.segments and decides the
 * route's mode: trie when every fast-path build limit is met, sequential
 * otherwise (empty literal segment, more than max_trie_pattern_segments
 * segments, or more than max_captures_per_route capture groups).
 */
void finalize_route(route_info& route) noexcept;

/**
 * @private
 * Best-effort kind sequence for a route that needs regexp matching, so it can
 * participate in the specificity order: custom "(...)" groups count as params,
 * full wildcards and modified ("?", "+", "*") groups terminate the sequence as
 * a wildcard tail. This mapping is an approximation and is called out as an
 * open question in the class documentation.
 */
void approximate_kind_sequence(const std::vector<url_pattern_part>& parts,
                               route_info& route);

/**
 * @private
 * Compiles the route set: builds the trie, the dispatch plans, the
 * whole-pathname exact table and the shape tables over the trie-mode routes,
 * and sets covered_by_static_table on the routes the exact table answers for.
 * Never fails: any table whose offline search fails is demoted to a slower
 * but correct plan.
 */
compiled_routes compile_route_set(std::vector<route_info>& routes);

/**
 * @private
 * Matches `pathname` against the compiled tables. When the input is out of
 * the fast-path contract, returns with within_fast_path == false and no
 * answer; the caller falls back to the sequential matcher.
 */
engine_result match_compiled(const compiled_routes& tables,
                             std::string_view pathname) noexcept;

/**
 * @private
 * Sequential reference matcher for one non-regexp route; matches any input
 * (no fast-path limits) with the same semantics as the compiled engine.
 * On a match, fills `result` (route index is NOT set) and returns true.
 */
bool match_route_sequential(const route_info& route, std::string_view pathname,
                            engine_result& result) noexcept;

/**
 * @private
 * True when route `a` (at insertion index `a_index`) outranks route `b` (at
 * `b_index`): lexicographically smaller kind sequence, insertion order as the
 * tiebreak.
 */
constexpr bool route_outranks(const route_info& a, size_t a_index,
                              const route_info& b, size_t b_index) noexcept {
  if (a.kind_sequence != b.kind_sequence) {
    return a.kind_sequence < b.kind_sequence;
  }
  if (a.kind_length != b.kind_length) {
    return a.kind_length < b.kind_length;
  }
  return a_index < b_index;
}

}  // namespace url_pattern_list_helpers

/**
 * The result of url_pattern_list::match. Captures are (offset, length)
 * slices of the pathname passed to match, in capture order: ":param" groups
 * left to right, then the "*" group, mirroring
 * url_pattern_list::group_names(). Routes matched through the regex provider
 * (patterns with custom regexp groups or modifiers) report capture_count == 0;
 * their group values can be obtained by executing the corresponding
 * ada::url_pattern. Routes with more than
 * url_pattern_list_helpers::max_captures_per_route groups report only the
 * first max_captures_per_route captures and set captures_truncated.
 */
struct url_pattern_list_match_result {
  using capture = url_pattern_list_helpers::capture;
  /** Index of the winning route in the creation vector, or -1 for no match. */
  int32_t route_index = -1;
  /** Number of valid entries in captures. */
  uint32_t capture_count = 0;
  /** True when the route has more groups than could be reported. */
  bool captures_truncated = false;
  std::array<capture, url_pattern_list_helpers::max_captures_per_route>
      captures{};

  [[nodiscard]] bool has_match() const noexcept { return route_index >= 0; }
};

/**
 * @brief A compiled set of URLPattern pathname patterns with one-shot
 * matching.
 *
 * Build once with create(), then call match() per request. Matching within
 * the fast-path limits is allocation-free and regex-free for routes written
 * in the static / ":param" / "*" subset; other routes are matched through
 * the regex provider and still participate in the priority order.
 *
 * Match priority is specificity order, not registration order: routes are
 * compared by their per-segment kind sequence (literal < ":param" < "*",
 * lexicographically from the first segment), with insertion order breaking
 * ties. This is the priority scheme of find-my-way (Fastify) and Express-
 * style routers. Whether a standardized URLPatternList should instead use
 * pure first-match-in-insertion-order semantics is an open question; the
 * compiled representation supports either, and the priority rule is
 * deliberately centralized in url_pattern_list_helpers::route_outranks.
 *
 * Scope (v1): the pathname component only. Other URL components are treated
 * as fully wildcarded; match() takes an already-extracted pathname (for
 * example ada::url_aggregator::get_pathname()). Inputs are matched as given
 * and are expected to be in canonical (percent-encoded) form; the pattern
 * side is canonicalized by the URLPattern pattern parser at create() time.
 *
 * @tparam regex_provider The regex implementation used only for routes that
 *         need URLPattern regexp semantics. Must satisfy
 *         url_pattern_regex::regex_concept.
 */
template <url_pattern_regex::regex_concept regex_provider>
class url_pattern_list {
 public:
  url_pattern_list() = default;

  /**
   * Builds the compiled route set. Each element of `pathname_patterns` is a
   * WHATWG URLPattern pathname pattern (for example "/users/:id" or a
   * "/static" prefix with a trailing "*"); its index in the vector is the
   * route id reported by
   * match(). Duplicate patterns are allowed; the smaller index wins.
   * All inputs must be valid UTF-8.
   *
   * @return The compiled list, or an error when a pattern is not a valid
   *         URLPattern pathname pattern (errors::type_error, matching the
   *         URLPattern constructor's behavior).
   */
  static tl::expected<url_pattern_list, errors> create(
      const std::vector<std::string_view>& pathname_patterns);

  /**
   * Matches a pathname against the set and returns the winning route with
   * its captures (see url_pattern_list_match_result). The fast path is
   * allocation-free; inputs beyond the fast-path limits are matched by the
   * sequential fallback with identical semantics.
   */
  [[nodiscard]] url_pattern_list_match_result match(
      std::string_view pathname) const;

  /** Number of routes in the set. */
  [[nodiscard]] size_t size() const noexcept { return routes_.size(); }

  /** The pattern string the route at `route_index` was created from. */
  [[nodiscard]] std::string_view pattern(size_t route_index) const
      ada_lifetime_bound {
    return patterns_[route_index];
  }

  /**
   * Capture group names of the route at `route_index`, in the capture order
   * of url_pattern_list_match_result::captures ("*" groups have numeric
   * names, per URLPattern).
   */
  [[nodiscard]] const std::vector<std::string>& group_names(
      size_t route_index) const ada_lifetime_bound {
    return routes_[route_index].group_names;
  }

 private:
  /** @private Sequential fallback over every route; used when the input
   * exceeds the fast-path limits. */
  [[nodiscard]] url_pattern_list_match_result match_sequential(
      std::string_view pathname) const;

  /** @private Tests one route (sequential or regexp mode) and, when it
   * matches and outranks `best`, replaces `best` with it. */
  void consider_route(uint32_t route_index, std::string_view pathname,
                      url_pattern_list_helpers::engine_result& best) const;

  /** @private The pattern strings, by route index. */
  std::vector<std::string> patterns_{};
  /** @private Per-route classification and priority data. */
  std::vector<url_pattern_list_helpers::route_info> routes_{};
  /** @private The compiled fast-path tables. */
  url_pattern_list_helpers::compiled_routes compiled_{};
  /** @private Routes the fast path cannot answer from the compiled tables
   * (sequential mode routes not covered by the exact table, and regexp mode
   * routes), in insertion order. */
  std::vector<uint32_t> auxiliary_routes_{};
  /** @private Compiled pathname components of the regexp-mode routes. */
  std::vector<url_pattern_component<regex_provider>> regexp_components_{};
};

}  // namespace ada
#endif  // ADA_INCLUDE_URL_PATTERN
#endif  // ADA_URL_PATTERN_LIST_H
