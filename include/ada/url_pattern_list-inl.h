/**
 * @file url_pattern_list-inl.h
 * @brief The url_pattern_list matcher (inline) and the class template's
 * member definitions.
 *
 * The walk over the compiled tables lives here, as ada_really_inline
 * functions, so that it inlines into url_pattern_list::match; the route-set
 * compiler that builds the tables is in its own translation unit
 * (src/url_pattern_list.cpp) and is not part of the public headers.
 */
#ifndef ADA_URL_PATTERN_LIST_INL_H
#define ADA_URL_PATTERN_LIST_INL_H

#include "ada/common_defs.h"
#include "ada/url_pattern_list.h"
#include "ada/url_pattern-inl.h"
#include "ada/url_pattern_helpers.h"
#include "ada/url_pattern_helpers-inl.h"

#include <bit>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if ADA_INCLUDE_URL_PATTERN
namespace ada::url_pattern_list_detail {

// ---- byte helpers ----------------------------------------------------------

// Unaligned 8-byte little-endian load; all 8 bytes must be readable. The
// byte-assembly fallback keeps big-endian targets correct (the compiler
// lowers it to a single load plus byte swap).
ada_really_inline uint64_t load8_le(const char* p) noexcept {
  if constexpr (std::endian::native == std::endian::little) {
    uint64_t x;
    std::memcpy(&x, p, 8);
    return x;
  } else {
    uint64_t x = 0;
    for (uint32_t j = 0; j < 8; j++) {
      x |= static_cast<uint64_t>(static_cast<uint8_t>(p[j])) << (8 * j);
    }
    return x;
  }
}

// Bytes [0, n) of p packed little-endian, zero-padded; reads exactly n
// bytes (n < 8). This is the byte-compare path for short tails.
ada_really_inline uint64_t gather_le(const char* p, uint32_t n) noexcept {
  uint64_t x = 0;
  for (uint32_t j = 0; j < n; j++) {
    x |= static_cast<uint64_t>(static_cast<uint8_t>(p[j])) << (8 * j);
  }
  return x;
}

// Mask selecting the low n bytes, 1 <= n <= 7.
constexpr uint64_t low_bytes_mask(uint32_t n) noexcept {
  return ~0ull >> (64 - 8 * n);
}

// ASCII case folding of n bytes from src into dst (the compiler vectorizes
// this loop). Only ASCII letters change: canonical pathnames are ASCII, and
// this is what a case-insensitive regular expression does over them.
inline void ascii_fold(const char* src, uint32_t n, char* dst) noexcept {
  for (uint32_t i = 0; i < n; i++) {
    const uint8_t c = static_cast<uint8_t>(src[i]);
    dst[i] = static_cast<char>(c | ((c >= 'A' && c <= 'Z') ? 0x20u : 0u));
  }
}

// ---- witness machinery -----------------------------------------------------
// Projection dispatch for wide trie nodes. A witness id names a feature of a
// byte string:
//   0..7   the byte at absolute offset id           (0 when out of range)
//   8..15  the byte at offset id-8 counted from the end
// A projection is three witness bytes plus the length packed into one
// uint64; a perfect multiplier turns it into a slot index. Builder and
// matcher call the same accessors and the same packing, so a slot table
// cannot disagree with the gather that reads it.

constexpr uint8_t length_byte(uint32_t len) noexcept {
  return len < 255u ? static_cast<uint8_t>(len) : static_cast<uint8_t>(255);
}

constexpr uint8_t witness_byte(const char* p, uint32_t len,
                               uint8_t id) noexcept {  // ids 0..15
  uint32_t o = id & 7u;
  bool in = o < len;
  uint32_t pos = (id & 8u) ? len - 1u - o : o;  // wraps when !in; masked then
  pos = in ? pos : 0u;
  uint8_t v = len ? static_cast<uint8_t>(p[pos]) : static_cast<uint8_t>(0);
  return in ? v : static_cast<uint8_t>(0);
}

constexpr uint64_t pack_projection(uint8_t f0, uint8_t f1, uint8_t f2,
                                   uint8_t f3) noexcept {
  return (static_cast<uint64_t>(f0) << 24) | (static_cast<uint64_t>(f1) << 16) |
         (static_cast<uint64_t>(f2) << 8) | static_cast<uint64_t>(f3);
}

// Perfect-multiplier slot index; b <= 12 everywhere, so the shift is in
// range and the product needs no modulus.
constexpr uint64_t slot_of(uint64_t proj, uint64_t multiplier,
                           uint8_t b) noexcept {
  return (proj * multiplier) >> (64 - b);
}

// Fixed-shape projection of one string: always 3 witness bytes plus the
// length. Duplicated ids add no information but keep the gather uniform.
constexpr uint64_t project(const char* p, uint32_t len,
                           uint16_t plan) noexcept {
  return pack_projection(
      witness_byte(p, len, static_cast<uint8_t>(plan & 15u)),
      witness_byte(p, len, static_cast<uint8_t>((plan >> 4) & 15u)),
      witness_byte(p, len, static_cast<uint8_t>((plan >> 8) & 15u)),
      length_byte(len));
}

// ---- segment scan ----------------------------------------------------------

// Splits the pathname into segments in one pass, in place: only segment
// starts are recorded, with a sentinel soff[nseg] = ulen + 1 so that
// seg_len(i) == soff[i + 1] - soff[i] - 1. Portable SWAR: 8 bytes per step,
// an exact zero-byte test on x ^ '/'-fill (no false positives, bytes >= 0x80
// included), and a byte-exact partial load for the tail, so the input is
// never over-read. Returns the segment count, or 0 when the input has more
// than max_fast_path_segments segments (the caller falls back to the
// sequential matcher). Requires ulen >= 1 and url[0] == '/'.
ada_really_inline uint32_t scan_segments(const char* url, uint32_t ulen,
                                         uint16_t* soff) noexcept {
  using url_pattern_list_limits::max_fast_path_segments;
  constexpr uint64_t slashes = 0x2F2F2F2F2F2F2F2Full;
  constexpr uint64_t low7 = 0x7F7F7F7F7F7F7F7Full;
  uint32_t nseg = 0;
  uint32_t start = 1;
  // Bit 7 of every byte of x that is zero, exactly: (b & 0x7F) + 0x7F has
  // bit 7 set iff the low bits are non-zero, b itself has it set iff b is
  // >= 0x80, and no lane can carry into its neighbour.
  const auto zero_lanes = [](uint64_t x) noexcept {
    return ~(((x & low7) + low7) | x | low7);
  };
  const auto emit = [&](uint64_t lanes, uint32_t base) noexcept {
    while (lanes) {
      const uint32_t pos =
          base + (static_cast<uint32_t>(std::countr_zero(lanes)) >> 3);
      if (nseg >= max_fast_path_segments) {
        return false;
      }
      soff[nseg++] = static_cast<uint16_t>(start);
      start = pos + 1;
      lanes &= lanes - 1;
    }
    return true;
  };
  uint32_t i = 1;
  for (; i + 8 <= ulen; i += 8) {
    const uint64_t lanes = zero_lanes(load8_le(url + i) ^ slashes);
    if (lanes != 0 && !emit(lanes, i)) {
      return 0;
    }
  }
  if (i < ulen) {  // tail of 1..7 bytes: zero padding is never a '/'
    const uint64_t lanes = zero_lanes(gather_le(url + i, ulen - i) ^ slashes);
    if (lanes != 0 && !emit(lanes, i)) {
      return 0;
    }
  }
  if (nseg >= max_fast_path_segments) {
    return 0;
  }
  soff[nseg++] = static_cast<uint16_t>(start);
  soff[nseg] = static_cast<uint16_t>(ulen + 1);  // sentinel
  return nseg;
}

// A "*" segment compiles to "(.*)" in the URLPattern regexp, and "." in an
// ECMAScript regular expression does not match a line terminator: the tail
// a wildcard captures must not contain LF or CR. Canonical pathnames never
// do (both are percent-encoded), so this only decides raw inputs.
ada_really_inline bool wildcard_tail_ok(const char* p, uint32_t n) noexcept {
  for (uint32_t j = 0; j < n; j++) {
    if (p[j] == '\n' || p[j] == '\r') {
      return false;
    }
  }
  return true;
}

// ---- verify / dispatch -----------------------------------------------------

// One input segment prepared for dispatch: its bytes, its length, and how
// many bytes are readable from p (to the end of the pathname).
struct segment_ref {
  const char* p;
  uint32_t len;
  uint32_t avail;
};

// Segment-vs-edge compare. Keys of 8..16 bytes verify from two whole-word
// loads inside the segment; shorter keys from one masked load when the
// input has 8 readable bytes, else from a byte gather (short tails such as
// "42" or "me"); longer keys through memcmp against the blob. An empty key
// (a pattern such as "/users/") matches exactly the empty segment.
ada_really_inline bool verify_edge(const edge_record& e, const segment_ref& s,
                                   const char* blob) noexcept {
  const uint32_t len = s.len;
  if (len != e.key_length) {
    return false;
  }
  if (len == 0) {
    return true;
  }
  if (len > 16) {
    return std::memcmp(s.p, blob + e.key_offset, len) == 0;
  }
  if (len >= 8) {
    return ((load8_le(s.p) ^ e.prefix) |
            (load8_le(s.p + len - 8) ^ e.suffix)) == 0;
  }
  const uint64_t x = s.avail >= 8 ? (load8_le(s.p) & low_bytes_mask(len))
                                  : gather_le(s.p, len);
  return x == e.prefix;
}

// The typed view of the arena the walk reads; derived once per match.
struct table_view {
  const node_record* nodes;
  const hash_record* hashes;
  const edge_record* edges;
  const uint8_t* slots;
  const char* blob;
  const uint16_t* root_index;
};

ada_really_inline table_view view_of(const compiled_routes& r) noexcept {
  return table_view{r.section<node_record>(r.nodes_offset),
                    r.section<hash_record>(r.hashes_offset),
                    r.section<edge_record>(r.edges_offset),
                    r.section<uint8_t>(r.slots_offset),
                    r.section<char>(r.blob_offset),
                    r.section<uint16_t>(r.root_index_offset)};
}

// Static-child dispatch: returns the child ordinal within the node or -1.
// Correctness never depends on the projection or the index: the candidate
// is always confirmed by a full segment compare, so a bad table can only
// cost time, never change an answer.
ada_really_inline int32_t dispatch_static(const table_view& t,
                                          const node_record& nd,
                                          const segment_ref& s) noexcept {
  const edge_record* e = t.edges + nd.first_child;
  switch (nd.dispatch) {
    case 0:
      return -1;
    case 1: {  // direct: up to 8 compares, each gated by the key length
      for (uint32_t j = 0; j < nd.n_static; j++) {
        if (verify_edge(e[j], s, t.blob)) {
          return static_cast<int32_t>(j);
        }
      }
      return -1;
    }
    case 2: {  // projection: gather -> multiply -> slot -> verify
      const hash_record& h = t.hashes[nd.hash_index];
      const uint64_t proj = project(s.p, s.len, h.witness_plan);
      const uint8_t ord =
          t.slots[h.slot_base + slot_of(proj, h.multiplier, h.slot_bits)];
      if (ord == 0xFF) {
        return -1;
      }
      return verify_edge(e[ord], s, t.blob) ? static_cast<int32_t>(ord) : -1;
    }
    case 4: {  // root first-byte index: jump to the run of children that
               // share the segment's first byte (children are sorted by it)
      if (s.len == 0) {
        return -1;  // no first byte; an indexed root has no empty key
      }
      const uint8_t b = static_cast<uint8_t>(s.p[0]);
      uint32_t j = t.root_index[b];
      if (j == 0xFFFF) {
        return -1;
      }
      for (; j < nd.n_static && static_cast<uint8_t>(e[j].prefix & 0xFFu) == b;
           j++) {
        if (verify_edge(e[j], s, t.blob)) {
          return static_cast<int32_t>(j);
        }
      }
      return -1;
    }
    default: {  // linear demotion rung (also carries fanout > 254)
      for (uint32_t j = 0; j < nd.n_static; j++) {
        if (verify_edge(e[j], s, t.blob)) {
          return static_cast<int32_t>(j);
        }
      }
      return -1;
    }
  }
}

// ---- the match residual ----------------------------------------------------

// Matches `pathname` against the compiled tables. When the input is out of
// the fast-path contract, returns with within_fast_path == false and no
// answer; the caller falls back to the sequential matcher.
ada_really_inline void match_compiled(const compiled_routes& r, const char* url,
                                      uint32_t ulen,
                                      engine_result& out) noexcept {
  using url_pattern_list_limits::max_fast_path_pathname_length;
  using url_pattern_list_limits::max_fast_path_segments;
  out = engine_result{};
  if (ulen == 0 || url[0] != '/' || ulen > max_fast_path_pathname_length) {
    out.within_fast_path = false;  // the sequential fallback decides
    return;
  }
  const table_view t = view_of(r);
  const route_record* routes = r.section<route_record>(r.routes_offset);

  // Segment scan; overflow means the input is beyond the fast path.
  uint16_t soff[max_fast_path_segments + 1];
  const uint32_t nseg = scan_segments(url, ulen, soff);
  if (nseg == 0) {
    out.within_fast_path = false;
    return;
  }
  const auto seg_len = [&](uint32_t i) {
    return static_cast<uint32_t>(soff[i + 1]) - soff[i] - 1u;
  };
  const auto seg_ref = [&](uint32_t i) {
    const uint32_t off = soff[i];
    return segment_ref{url + off, seg_len(i), ulen - off};
  };

  // Trie walk with an explicit bounded backtrack stack. Every node offers
  // the same three alternatives in the compiled priority order (static
  // child, param child, wildcard); a backtrack record stores the resume
  // point, and a record is pushed only when the node still has an untried
  // alternative, so the stack never exceeds the walk depth. Edges encoded
  // as -2 - route are pure-leaf shortcuts.
  enum alternative : uint16_t {
    alt_static = 0,
    alt_param = 1,
    alt_wild = 2,
    alt_none = 3
  };
  struct backtrack {
    int32_t node;
    uint16_t i;
    uint16_t resume;
  };
  backtrack stack[max_fast_path_segments + 1];
  uint32_t sp = 0;
  int32_t node = 0;
  uint32_t i = 0;
  uint32_t alt = alt_static;
  int32_t route = -1;
  uint32_t wild_from = 0;
  bool wild = false;
  for (;;) {
    const node_record& nd = t.nodes[static_cast<size_t>(node)];
    if (alt == alt_static) {
      if (i == nseg) {
        if (nd.terminal_route >= 0) {
          route = nd.terminal_route;
          break;
        }
        alt = alt_none;
      } else {
        const int32_t ord = dispatch_static(t, nd, seg_ref(i));
        if (ord >= 0) {
          const int32_t nxt = t.edges[static_cast<size_t>(nd.first_child) +
                                      static_cast<size_t>(ord)]
                                  .node;
          if (nxt >= 0) {
            if (nd.has_alternative) {
              stack[sp++] = {node, static_cast<uint16_t>(i), alt_param};
            }
            node = nxt;
            i++;
            continue;
          }
          // Pure-leaf shortcut.
          if (i + 1 == nseg) {
            route = -2 - nxt;
            break;
          }
          alt = alt_param;  // dead end: fall through to this node's fallbacks
        } else {
          alt = alt_param;
        }
      }
    }
    if (alt == alt_param) {
      const int32_t pc = nd.param_child;
      if (pc != -1 && seg_len(i) > 0) {
        if (pc >= 0) {
          if (nd.wild_route >= 0) {
            stack[sp++] = {node, static_cast<uint16_t>(i), alt_wild};
          }
          node = pc;
          i++;
          alt = alt_static;
          continue;
        }
        // Pure-leaf param shortcut.
        if (i + 1 == nseg) {
          route = -2 - pc;
          break;
        }
        alt = alt_wild;  // only the wildcard remains here
      } else {
        alt = alt_wild;
      }
    }
    if (alt == alt_wild) {
      if (nd.wild_route >= 0 &&
          wildcard_tail_ok(url + soff[i], ulen - soff[i])) {
        route = nd.wild_route;
        wild_from = i;
        wild = true;
        break;
      }
      // No alternative left at this node: resume from the backtrack stack
      // (alt is overwritten by the popped record).
    }
    if (sp == 0) {
      break;  // nothing to resume: miss
    }
    --sp;
    node = stack[sp].node;
    i = stack[sp].i;
    alt = stack[sp].resume;
  }

  out.route = route;
  if (route >= 0) {  // capture extraction: params first, wildcard tail last
    const route_record& rm = routes[static_cast<size_t>(route)];
    uint32_t nc = 0;
    for (uint32_t k = 0; k < rm.n_params; k++) {
      const uint32_t p = rm.param_positions[k];
      out.captures[nc++] = {soff[p], seg_len(p)};
    }
    if (wild) {
      out.captures[nc++] = {soff[wild_from], ulen - soff[wild_from]};
    }
    out.capture_count = nc;
  }
}

}  // namespace ada::url_pattern_list_detail

namespace ada {

template <url_pattern_regex::regex_concept regex_provider>
tl::expected<url_pattern_list<regex_provider>, errors>
url_pattern_list<regex_provider>::create(
    std::vector<std::string>&& pathname_patterns, bool ignore_case) {
  url_pattern_list list{};
  list.patterns_ = std::move(pathname_patterns);
  auto compiled = url_pattern_list_detail::compile_pathname_patterns(
      list.patterns_, ignore_case);
  if (!compiled) {
    return tl::unexpected(compiled.error());
  }
  list.compiled_ = std::move(*compiled);
  return list;
}

template <url_pattern_regex::regex_concept regex_provider>
void url_pattern_list<regex_provider>::consider_route(
    uint32_t route_index, std::string_view pathname, std::string_view probe,
    bool fold_input, url_pattern_list_detail::engine_result& best,
    std::vector<std::optional<std::string>>& best_groups) const {
  namespace detail = url_pattern_list_detail;
  const detail::route_record* routes =
      compiled_.section<detail::route_record>(compiled_.routes_offset);
  const detail::route_record& candidate = routes[route_index];
  // Only test candidates that would outrank the current best.
  if (best.route >= 0) {
    const detail::route_record& current =
        routes[static_cast<size_t>(best.route)];
    if (!detail::outranks(candidate.kind_sequence, candidate.kind_length,
                          route_index, current.kind_sequence,
                          current.kind_length,
                          static_cast<size_t>(best.route))) {
      return;
    }
  }
  if (candidate.mode == detail::route_mode::regexp) {
    // A route whose certain segment shape does not fit the input cannot
    // match at all: skip the provider.
    if (!detail::match_regexp_shape(compiled_, route_index, probe,
                                    fold_input)) {
      return;
    }
    // URLPattern's own test/exec split: regex_match answers yes/no (this is
    // what rejects a non-matching route cheaply; a regex_search miss can
    // cost a scan over every start position), and regex_search then
    // produces the group values exactly as url_pattern::exec does.
    const url_pattern_component<regex_provider>& component =
        regexp_components_[static_cast<size_t>(candidate.regexp_component)];
    if (!component.fast_test(pathname)) {
      return;
    }
    auto groups = component.fast_match(pathname);
    if (groups) {
      best = detail::engine_result{};
      best.route = static_cast<int32_t>(route_index);
      best_groups = std::move(*groups);
    }
  } else {
    detail::engine_result scratch{};
    if (detail::match_route_sequential(compiled_, route_index, probe,
                                       fold_input, scratch)) {
      scratch.route = static_cast<int32_t>(route_index);
      best = scratch;
      best_groups.clear();
    }
  }
}

template <url_pattern_regex::regex_concept regex_provider>
url_pattern_list_match_result url_pattern_list<regex_provider>::match(
    std::string_view pathname) const {
  namespace detail = url_pattern_list_detail;
  using url_pattern_list_limits::max_fast_path_pathname_length;
  // With ignore_case the compiled literals are ASCII-folded, so the fast
  // path probes a folded copy of the input (offsets are unchanged, so the
  // captures still slice the original). Inputs beyond the fast-path length
  // are folded on the fly by the sequential matcher instead.
  char folded[max_fast_path_pathname_length];
  std::string_view probe = pathname;
  bool fold_input = false;
  if (compiled_.ignore_case) {
    if (pathname.size() <= max_fast_path_pathname_length) {
      detail::ascii_fold(pathname.data(),
                         static_cast<uint32_t>(pathname.size()), folded);
      probe = std::string_view(folded, pathname.size());
    } else {
      fold_input = true;
    }
  }
  detail::engine_result best{};
  std::vector<std::optional<std::string>> best_groups{};
  detail::match_compiled(compiled_, probe.data(),
                         static_cast<uint32_t>(probe.size()), best);
  const uint32_t* aux = compiled_.section<uint32_t>(compiled_.aux_offset);
  if (!best.within_fast_path) {
    // The input exceeds a fast-path limit (length, segment count, or no
    // leading '/'): the sequential fallback matches every route with
    // identical priority semantics.
    best = detail::engine_result{};
    for (size_t i = 0; i < patterns_.size(); i++) {
      consider_route(static_cast<uint32_t>(i), pathname, probe, fold_input,
                     best, best_groups);
    }
  } else if (best.route >= 0) {
    // A fast-path winner is final except for the auxiliary routes recorded
    // at creation as able to outrank it (usually none).
    const detail::route_record& winner =
        compiled_.section<detail::route_record>(
            compiled_.routes_offset)[static_cast<size_t>(best.route)];
    for (uint32_t k = 0; k < winner.challenger_count; k++) {
      consider_route(aux[winner.challenger_first + k], pathname, probe,
                     fold_input, best, best_groups);
    }
  } else {
    // A fast-path miss: any auxiliary route may still match.
    for (uint32_t k = 0; k < compiled_.n_aux_all; k++) {
      consider_route(aux[k], pathname, probe, fold_input, best, best_groups);
    }
  }
  url_pattern_list_match_result result{};
  result.route_index = best.route;
  if (best.route >= 0) {
    const detail::route_record& winner =
        compiled_.section<detail::route_record>(
            compiled_.routes_offset)[static_cast<size_t>(best.route)];
    if (winner.mode == detail::route_mode::regexp) {
      result.regexp_route = true;
      result.regexp_groups = std::move(best_groups);
    } else {
      result.capture_count = best.capture_count;
      result.captures_truncated = best.captures_truncated;
      result.captures = best.captures;
    }
  }
  return result;
}

}  // namespace ada
#endif  // ADA_INCLUDE_URL_PATTERN
#endif  // ADA_URL_PATTERN_LIST_INL_H
