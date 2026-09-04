/**
 * @file url_pattern_list.h
 * @brief Compiled set-level matching over URLPattern pathname patterns.
 *
 * `ada::url_pattern_list` answers the question "which of my N routes matches
 * this pathname, and what are the parameter values?" in a single walk
 * instead of a loop of N `url_pattern::exec` calls. The whole route set is
 * compiled once, by ada::parse_url_pattern_list, into a segment trie with
 * per-node dispatch (direct compares for small fanouts, a first-byte index
 * at the root, perfect-hash projection for wide nodes). Matching a pathname
 * against the compiled set is allocation-free and does not execute any
 * regular expression for routes written in the common static / ":param" /
 * "*" subset; other routes are matched through the regex provider, exactly
 * as ada::url_pattern does.
 *
 * This implements the route-set ("URLPatternList") use case discussed in
 * https://github.com/whatwg/urlpattern/issues/166 for the pathname component.
 *
 * Correctness does not depend on the fast path: inputs or routes that exceed
 * the fast-path limits (documented on the constants in
 * `ada::url_pattern_list_limits`) are matched by a sequential fallback with
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
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if ADA_INCLUDE_URL_PATTERN
namespace ada {

/**
 * The limits of the url_pattern_list fast path. None of them changes what a
 * list matches: routes and inputs beyond a limit are matched by a sequential
 * fallback with identical semantics.
 * @namespace ada::url_pattern_list_limits
 */
namespace url_pattern_list_limits {

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

}  // namespace url_pattern_list_limits

/**
 * The result of url_pattern_list::match. A winning route reports its group
 * values in one of two forms, mirroring url_pattern_list::group_names():
 *
 * - Routes in the static / ":param" / "*" subset report zero-allocation
 *   captures: (offset, length) slices of the pathname passed to match, in
 *   capture order (":param" groups left to right, then the "*" group).
 *   `regexp_route` is false and `regexp_groups` is empty.
 * - Routes matched through the regex provider (patterns with custom regexp
 *   groups or "?" / "+" / "*" modifiers) report the group values the
 *   provider's regex_search returned, exactly as url_pattern::exec would for
 *   the pathname component: `regexp_route` is true, `regexp_groups[i]` is the
 *   value of group_names(route_index)[i] (nullopt for a group that did not
 *   participate), and capture_count is 0.
 *
 * Routes with more than url_pattern_list_limits::max_captures_per_route
 * groups report only the first max_captures_per_route slices and set
 * captures_truncated.
 */
struct url_pattern_list_match_result {
  /** One capture: an (offset, length) slice of the matched pathname. */
  struct capture {
    uint32_t offset = 0;
    uint32_t length = 0;
  };
  /** Index of the winning route in the creation order, or -1 for no match. */
  int32_t route_index = -1;
  /** Number of valid entries in captures. */
  uint32_t capture_count = 0;
  /** True when the route has more groups than could be reported as slices. */
  bool captures_truncated = false;
  /** True when the winning route was matched through the regex provider; its
   * group values are in regexp_groups. */
  bool regexp_route = false;
  std::array<capture, url_pattern_list_limits::max_captures_per_route>
      captures{};
  /** Group values of a regexp route, as returned by the provider. */
  std::vector<std::optional<std::string>> regexp_groups{};

  [[nodiscard]] bool has_match() const noexcept { return route_index >= 0; }
};

/**
 * @private
 * The compiled tables url_pattern_list::match walks, and the inline matcher
 * over them (url_pattern_list-inl.h). Nothing here is part of the supported
 * API. The route-set compiler that produces these tables is not part of the
 * public headers at all (src/url_pattern_list_compiler.h).
 * @namespace ada::url_pattern_list_detail
 */
namespace url_pattern_list_detail {

/** @private One trie node. Nodes with a projection dispatch keep their hash
 * payload in a separate hash_record, so the common 0/1/direct nodes stay at
 * 24 bytes. */
struct node_record {
  // First static edge (edges are laid out per node, contiguously).
  int32_t first_child = 0;
  // Child node index, -2 - route (pure-leaf shortcut), or -1.
  int32_t param_child = -1;
  // Route index of a "*" ending at this prefix, or -1.
  int32_t wild_route = -1;
  // Route ending exactly here, or -1.
  int32_t terminal_route = -1;
  uint16_t n_static = 0;
  // 0 none, 1 direct compares, 2 projection, 3 linear scan, 4 first-byte
  // index (root only).
  uint8_t dispatch = 0;
  // 1 if the node still has a param/wildcard alternative to backtrack to.
  uint8_t has_alternative = 0;
  // Index of the node's hash_record (dispatch == 2 only).
  uint32_t hash_index = 0;
};

/** @private Projection-dispatch payload of a hashed node. */
struct hash_record {
  uint64_t multiplier = 0;
  uint32_t slot_base = 0;
  // Witness plan: 3 nibble ids | count << 12 | use_len << 14.
  uint16_t witness_plan = 0;
  // Slot table size == 1 << slot_bits.
  uint8_t slot_bits = 0;
  uint8_t reserved = 0;
};

/** @private One static edge; keys <= 16 bytes verify from the packed
 * windows alone. */
struct edge_record {
  // Key bytes [0, min(8, len)), little-endian, zero-padded.
  uint64_t prefix = 0;
  // Key bytes [max(0, len - 8), len), little-endian, zero-padded.
  uint64_t suffix = 0;
  // Child node index; negative values encode -2 - route pure-leaf shortcuts.
  int32_t node = -1;
  // Full key in the blob (read only when key_length > 16).
  uint32_t key_offset = 0;
  uint16_t key_length = 0;
};

/** @private How one route of the set is matched. */
enum class route_mode : uint8_t {
  // Compiled into the trie fast path.
  trie = 0,
  // Safe static/":param"/"*" syntax beyond a fast-path build limit: matched
  // by the sequential segment matcher.
  sequential = 1,
  // Needs URLPattern regexp semantics: matched through the regex provider.
  regexp = 2,
};

/** @private Everything the matcher knows about one route after a hit. */
struct route_record {
  // Packed per-segment kinds, two bits per segment, most significant first;
  // (kind_sequence, kind_length, route index) compared as a tuple is the
  // specificity order.
  uint64_t kind_sequence = 0;
  // Sequential-mode routes: their segments in the segment table.
  uint32_t segment_first = 0;
  uint32_t segment_count = 0;
  // Auxiliary routes that can outrank this route when it wins the fast
  // path: a range of the aux table (usually empty).
  uint32_t challenger_first = 0;
  uint32_t challenger_count = 0;
  // Ordinal among the regexp-mode routes, or -1.
  int32_t regexp_component = -1;
  uint8_t kind_length = 0;
  route_mode mode = route_mode::sequential;
  // Trie-mode routes: capture positions.
  uint8_t n_params = 0;
  uint8_t wild = 0;
  std::array<uint8_t, url_pattern_list_limits::max_captures_per_route>
      param_positions{};
};

/** @private One pattern segment of a sequential-mode route. */
struct segment_record {
  uint32_t text_offset = 0;
  uint32_t text_length = 0;
  // 0 literal, 1 ":param", 2 "*".
  uint8_t kind = 0;
};

/**
 * @private
 * The compiled route set: one arena holding every table, addressed by
 * section offsets, plus the per-route group names. Sections are 8-byte
 * aligned; the blob is zero-padded by 8 bytes so short key windows can be
 * loaded whole.
 */
struct compiled_routes {
  std::vector<uint8_t> arena{};
  std::vector<std::vector<std::string>> group_names{};
  uint32_t nodes_offset = 0;
  uint32_t hashes_offset = 0;
  uint32_t edges_offset = 0;
  uint32_t slots_offset = 0;
  uint32_t blob_offset = 0;
  uint32_t routes_offset = 0;
  uint32_t segments_offset = 0;
  uint32_t aux_offset = 0;
  uint32_t root_index_offset = 0;
  uint32_t n_routes = 0;
  // All auxiliary routes (regexp mode and sequential mode) in insertion
  // order: the aux table's first n_aux_all entries; challenger ranges
  // follow.
  uint32_t n_aux_all = 0;
  uint8_t ignore_case = 0;

  template <typename T>
  [[nodiscard]] const T* section(uint32_t offset) const noexcept {
    return reinterpret_cast<const T*>(arena.data() + offset);
  }
};

/** @private Result of the fast-path engine or of the sequential matcher. */
struct engine_result {
  using capture = url_pattern_list_match_result::capture;
  int32_t route = -1;
  uint32_t capture_count = 0;
  // False when the input exceeded a fast-path limit and the caller must run
  // the sequential fallback over the whole route set.
  bool within_fast_path = true;
  bool captures_truncated = false;
  std::array<capture, url_pattern_list_limits::max_captures_per_route>
      captures{};
};

/**
 * @private
 * Parses and compiles a set of pathname patterns (already base-URL
 * processed). Routes that need the regex provider come back with
 * route_record::regexp_component set to their ordinal in insertion order;
 * the caller compiles those components and fills their group names.
 */
tl::expected<compiled_routes, errors> compile_pathname_patterns(
    std::span<const std::string> patterns, bool ignore_case);

/**
 * @private
 * Sequential reference matcher for one non-regexp route of the compiled set;
 * matches any input (no fast-path limits) with the same semantics as the
 * compiled engine. With `fold_input`, input bytes are ASCII case-folded on
 * the fly (the compiled literals are already folded). On a match, fills
 * `result` (route index is NOT set) and returns true.
 */
bool match_route_sequential(const compiled_routes& tables, uint32_t route,
                            std::string_view pathname, bool fold_input,
                            engine_result& result) noexcept;

/**
 * @private
 * Cheap pre-check for a regexp-mode route before running the provider: the
 * part of the route's segment shape that is certain (see the compiler's
 * approximate_kind_sequence) must fit the pathname -- its anchored literal
 * segments, and its exact segment count when every group is a ":name"
 * segment wildcard. False proves the regular expression cannot match.
 */
bool match_regexp_shape(const compiled_routes& tables, uint32_t route,
                        std::string_view pathname, bool fold_input) noexcept;

/**
 * @private
 * True when route `a` (at insertion index `a_index`) outranks route `b` (at
 * `b_index`): lexicographically smaller kind sequence, insertion order as the
 * tiebreak.
 */
constexpr bool outranks(uint64_t a_sequence, uint32_t a_length, size_t a_index,
                        uint64_t b_sequence, uint32_t b_length,
                        size_t b_index) noexcept {
  if (a_sequence != b_sequence) {
    return a_sequence < b_sequence;
  }
  if (a_length != b_length) {
    return a_length < b_length;
  }
  return a_index < b_index;
}

}  // namespace url_pattern_list_detail

/**
 * @brief A compiled set of URLPattern pathname patterns with one-shot
 * matching.
 *
 * Build once with ada::parse_url_pattern_list, then call match() per
 * request. Matching within the fast-path limits is allocation-free and
 * regex-free for routes written in the static / ":param" / "*" subset; other
 * routes are matched through the regex provider (the same regex_search call
 * url_pattern::exec makes) and still participate in the priority order.
 *
 * Match priority is specificity order, not registration order: routes are
 * compared by their per-segment kind sequence (literal < ":param" < "*",
 * lexicographically from the first segment), with insertion order breaking
 * ties. This is the priority scheme of find-my-way (Fastify) and Express-
 * style routers. Whether a standardized URLPatternList should instead use
 * pure first-match-in-insertion-order semantics is an open question; the
 * compiled representation supports either, and the priority rule is
 * deliberately centralized in url_pattern_list_detail::outranks.
 *
 * Scope (v1): the pathname component only. Other URL components are treated
 * as fully wildcarded; match() takes an already-extracted pathname (for
 * example ada::url_aggregator::get_pathname()). Inputs are matched as given
 * and are expected to be in canonical (percent-encoded) form; the pattern
 * side is canonicalized by the URLPattern pattern parser at creation. The
 * subset follows the URLPattern regexp it stands for: a ":param" segment
 * ("[^/]+?") is one non-empty segment, and a "*" tail ("(.*)") matches any
 * bytes except the line terminators LF and CR, which "." never matches.
 *
 * With url_pattern_options::ignore_case, regexp routes are compiled through
 * the provider with the flag set (as url_pattern does), and the static /
 * ":param" / "*" subset compares literal segments with ASCII case folding,
 * which is what a case-insensitive regular expression does over the ASCII
 * text of a canonical pathname.
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
   * Matches a pathname against the set and returns the winning route with
   * its captures (see url_pattern_list_match_result). The fast path is
   * allocation-free; inputs beyond the fast-path limits are matched by the
   * sequential fallback with identical semantics.
   */
  [[nodiscard]] url_pattern_list_match_result match(
      std::string_view pathname) const;

  /** Number of routes in the set. */
  [[nodiscard]] size_t size() const noexcept { return patterns_.size(); }

  /** The pathname pattern string the route at `route_index` was created
   * from (after base URL processing, if a base URL was given). */
  [[nodiscard]] std::string_view pattern(size_t route_index) const
      ada_lifetime_bound {
    return patterns_[route_index];
  }

  /**
   * Capture group names of the route at `route_index`, in the order of
   * url_pattern_list_match_result::captures / regexp_groups ("*" groups have
   * numeric names, per URLPattern).
   */
  [[nodiscard]] const std::vector<std::string>& group_names(
      size_t route_index) const ada_lifetime_bound {
    return compiled_.group_names[route_index];
  }

  /** The ignore_case option the set was created with. */
  [[nodiscard]] bool ignore_case() const noexcept {
    return compiled_.ignore_case != 0;
  }

  template <url_pattern_regex::regex_concept P>
  friend tl::expected<url_pattern_list<P>, errors> parse_url_pattern_list(
      std::span<const std::string_view> pathname_patterns,
      const std::string_view* base_url, const url_pattern_options* options);

  template <url_pattern_regex::regex_concept P>
  friend tl::expected<url_pattern_list<P>, errors> parse_url_pattern_list(
      std::span<const url_pattern<P>> patterns);

 private:
  /** @private Compiles the (already processed) pattern strings; the regexp
   * components are then supplied by the caller in insertion order. */
  static tl::expected<url_pattern_list, errors> create(
      std::vector<std::string>&& pathname_patterns, bool ignore_case);

  /** @private Tests one auxiliary route (sequential or regexp mode) and,
   * when it matches and outranks `best`, replaces `best` with it. `probe`
   * is the (possibly case-folded) pathname for the sequential matcher,
   * `pathname` the original for the provider. */
  void consider_route(
      uint32_t route_index, std::string_view pathname, std::string_view probe,
      bool fold_input, url_pattern_list_detail::engine_result& best,
      std::vector<std::optional<std::string>>& best_groups) const;

  /** @private The pattern strings, by route index. */
  std::vector<std::string> patterns_{};
  /** @private The compiled tables. */
  url_pattern_list_detail::compiled_routes compiled_{};
  /** @private Compiled pathname components of the regexp-mode routes, in
   * insertion order. */
  std::vector<url_pattern_component<regex_provider>> regexp_components_{};
};

}  // namespace ada
#endif  // ADA_INCLUDE_URL_PATTERN
#endif  // ADA_URL_PATTERN_LIST_H
