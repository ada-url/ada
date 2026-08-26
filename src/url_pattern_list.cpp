/**
 * @file url_pattern_list.cpp
 * @brief Route-set compiler and matcher backing ada::url_pattern_list.
 *
 * The provider-independent engine: classification of URLPattern part lists
 * into pattern segments, the build-time compiler (segment trie, per-node
 * witness dispatch, whole-pathname exact table, shape tables), the fast-path
 * matcher, and the sequential reference matcher used beyond the fast-path
 * limits.
 *
 * The design was developed and measured as a standalone prototype; every
 * dispatch decision is made at build time so that the per-request residual is
 * a whole-pathname probe, a segment scan, a shape probe, and a trie walk with
 * bounded backtracking. Offline searches (witness plans, perfect multipliers)
 * that fail demote the affected table to a linear scan: slower, never
 * incorrect.
 */
#include "ada/url_pattern_list.h"

#include <algorithm>
#include <bit>
#include <cstring>

#if ADA_INCLUDE_URL_PATTERN

// The NEON segment scan is a fast path only; define
// ADA_URL_PATTERN_LIST_NO_NEON to force the portable scalar scan.
#if defined(__ARM_NEON) && !defined(ADA_URL_PATTERN_LIST_NO_NEON)
#include <arm_neon.h>
#define ADA_URL_PATTERN_LIST_USE_NEON 1
#else
#define ADA_URL_PATTERN_LIST_USE_NEON 0
#endif

namespace ada::url_pattern_list_helpers {

namespace {

// Depth cap of the shape machinery == the trie pattern depth cap.
constexpr uint32_t max_shape_statics = max_trie_pattern_segments - 1;
constexpr uint32_t max_shape_runs = max_captures_per_route + 1;

// ---- shared witness machinery ---------------------------------------------
// One witness alphabet and one projection packing serve the per-node
// dispatch, the whole-pathname exact table, and the shape groups. A witness
// id names a feature of a byte string:
//   0..7   the byte at absolute offset id           (0 when out of range)
//   8..15  the byte at offset id-8 counted from the end
//   16     the string's length, saturated to 255
// A projection is four feature bytes packed into one uint64; a perfect
// multiplier turns it into a slot index. Builder and matcher call the same
// accessors and the same packing, so a slot table cannot disagree with the
// gather that reads it.

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

// The full alphabet, ids 0..16 (16 = length). Shape plans use this; the
// 16-bit single-string plans below can only name ids 0..15 and always pack
// the length unconditionally.
constexpr uint8_t witness(const char* p, uint32_t len, uint8_t id) noexcept {
  return id == 16 ? length_byte(len) : witness_byte(p, len, id);
}

// Matcher-side twin of `witness`, reading the segment [lo, hi - 1) of `url`
// (lo/hi are consecutive segment offsets, so the length is hi - lo - 1).
// Deliberately mask arithmetic, not a ternary: witness ids vary per shape
// group, so a data-dependent branch here mispredicts on the probe path. The
// byte load is unconditional from an address masked to 0 on the unselected
// path; url[0] is the leading '/', which every fast-path input has.
inline uint8_t witness_in_url(const char* url, uint32_t lo, uint32_t hi,
                              uint8_t id) noexcept {
  const uint32_t len = hi - lo - 1u;
  const uint32_t o = id & 7u;
  const uint32_t m_len =
      0u - static_cast<uint32_t>(id >> 4);  // all-ones <=> id == 16
  const uint32_t m_in =
      (0u - static_cast<uint32_t>(o < len)) & ~m_len;  // byte selected
  const uint32_t pos = (id & 8u) ? hi - 2u - o : lo + o;
  const uint8_t b = static_cast<uint8_t>(url[pos & m_in]);
  return static_cast<uint8_t>((length_byte(len) & m_len) | (b & m_in));
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

// Witness plan for single-string tables: nibbles 0..2 hold witness ids
// (distinct ids first, remaining slots duplicating id 0 so the runtime
// gather is fixed-shape and branch-free); bits 12..14 are metadata.
constexpr uint16_t pack_witness_plan(const uint8_t* ids, uint32_t n_ids,
                                     bool use_len) noexcept {
  uint16_t w = 0;
  for (uint32_t j = 0; j < 3; j++) {
    w = static_cast<uint16_t>(
        w | static_cast<uint16_t>((j < n_ids ? ids[j] : ids[0]) & 15u)
                << (4 * j));
  }
  w = static_cast<uint16_t>(w | static_cast<uint16_t>(n_ids << 12));
  if (use_len) {
    w = static_cast<uint16_t>(w | static_cast<uint16_t>(1) << 14);
  }
  return w;
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

// Bytes [from, min(from + 8, len)) of a key, packed little-endian and
// zero-padded; the build-time twin of the matcher's window load.
constexpr uint64_t pack_window_le(const char* p, uint32_t len,
                                  uint32_t from) noexcept {
  uint64_t x = 0;
  for (uint32_t j = 0; j < 8 && from + j < len; j++) {
    x |= static_cast<uint64_t>(static_cast<uint8_t>(p[from + j])) << (8 * j);
  }
  return x;
}

// Unaligned 8-byte little-endian load; source must be padded-readable. The
// byte-assembly fallback keeps big-endian targets correct (the compiler
// lowers it to a single load plus byte swap).
inline uint64_t load8_le(const char* p) noexcept {
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

// Byte equality with memcmp semantics but no libc call: overlapping loads,
// every load fully inside [x, x + len).
inline bool eq_bytes(const char* a, const char* b, size_t len) noexcept {
  if (len < 4) {
    if (len == 0) {
      return true;
    }
    return a[0] == b[0] && a[len - 1] == b[len - 1] &&
           a[len >> 1] == b[len >> 1];
  }
  if (len <= 8) {
    uint32_t a0, a1, b0, b1;
    std::memcpy(&a0, a, 4);
    std::memcpy(&b0, b, 4);
    std::memcpy(&a1, a + len - 4, 4);
    std::memcpy(&b1, b + len - 4, 4);
    return ((a0 ^ b0) | (a1 ^ b1)) == 0;
  }
  uint64_t acc = 0;
  size_t i = 0;
  for (; i + 8 < len; i += 8) {  // last <= 8 bytes handled by the tail load
    uint64_t x, y;
    std::memcpy(&x, a + i, 8);
    std::memcpy(&y, b + i, 8);
    acc |= x ^ y;
  }
  uint64_t x, y;
  std::memcpy(&x, a + len - 8, 8);
  std::memcpy(&y, b + len - 8, 8);
  return (acc | (x ^ y)) == 0;
}

// One input segment prepared for dispatch. `p` points at the segment for
// strictly-bounded byte loads; `vp` is a window-safe base for whole-uint64
// loads: normally p itself, or a pointer into a zero-padded copy of the
// pathname's tail when the 8-byte window would cross the end of the input.
struct segment_ref {
  const char* p;
  const char* vp;
  uint32_t len;
};

// Segment-vs-edge compare. Branch-free for keys <= 16 bytes; longer keys
// take the blob path. Trie keys are never empty (classification sends empty
// literal segments to the sequential path), so key_length >= 1 here.
inline bool verify_edge(const trie_edge& e, const segment_ref& s,
                        const char* blob) noexcept {
  const uint32_t len = s.len;
  if (len != e.key_length) {
    return false;
  }
  if (len <= 16) [[likely]] {
    uint64_t m = len >= 8 ? ~0ull : (~0ull >> (64 - 8 * len));
    uint32_t so = len >= 8 ? len - 8 : 0;
    return (((load8_le(s.vp) & m) ^ e.prefix) |
            ((load8_le(s.vp + so) & m) ^ e.suffix)) == 0;
  }
  return std::memcmp(s.p, blob + e.key_offset, len) == 0;
}

// Shape-entry verify: the entry key is the pattern's static segments joined
// with '/'. Compared run by run: a maximal block of consecutive static
// positions is one contiguous pathname byte range (interior '/' separators
// included). Segments are '/'-free and pattern statics are non-empty, so
// byte equality of the joined strings forces segment-wise equality; the
// inter-run '/' checks pin the run boundaries and the final length check
// rejects leftovers. Params are checked by the caller (non-empty only).
inline bool verify_shape(const shape_group& g, const static_entry& e,
                         const char* url, const uint16_t* soff,
                         const char* blob) noexcept {
  uint32_t cum = 0;
  for (uint32_t r = 0; r < g.n_runs; r++) {
    const uint32_t p0 = g.run_first[r], p1 = g.run_last[r];
    const uint32_t rl = static_cast<uint32_t>(soff[p1 + 1]) - 1u - soff[p0];
    if (r) {
      if (cum >= e.length || blob[e.offset + cum] != '/') {
        return false;  // bound before the read
      }
      cum++;
    }
    if (cum + rl > e.length) {
      return false;
    }
    if (!eq_bytes(url + soff[p0], blob + e.offset + cum, rl)) {
      return false;
    }
    cum += rl;
  }
  return cum == e.length;
}

// ---- the match residual ----------------------------------------------------

// Splits the pathname into segments in one pass, in place: only segment
// starts are recorded, with a sentinel soff[nseg] = ulen + 1 so that
// seg_len(i) == soff[i + 1] - soff[i] - 1. The NEON variant walks 16-byte
// chunks plus one overlapped tail chunk, so the source is never over-read.
// Returns the segment count, or 0 when the input has more than
// max_fast_path_segments segments (the caller falls back to the sequential
// matcher). Requires ulen >= 1 and url[0] == '/'.
ada_really_inline uint32_t scan_segments(const char* url, uint32_t ulen,
                                         uint16_t* soff) noexcept {
  uint32_t nseg = 0;
  uint32_t s = 1;
  bool overflow = false;
#if ADA_URL_PATTERN_LIST_USE_NEON
  const uint8x16_t slash = vdupq_n_u8('/');
  auto emit = [&](uint64_t m, uint32_t base) {  // one start per '/' lane
    while (m) {
      const uint32_t tpos =
          base + static_cast<uint32_t>(__builtin_ctzll(m) >> 2);
      m &= ~(0xFull << ((tpos - base) * 4));
      if (nseg >= max_fast_path_segments) {
        overflow = true;
        return;
      }
      soff[nseg++] = static_cast<uint16_t>(s);
      s = tpos + 1;
    }
  };
  if (ulen >= 16) {
    uint32_t i = 0;
    for (; i + 16 <= ulen; i += 16) {
      const uint8x16_t v0 = vld1q_u8(reinterpret_cast<const uint8_t*>(url) + i);
      uint64_t m =
          vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(
                            vreinterpretq_u16_u8(vceqq_u8(v0, slash)), 4)),
                        0);
      if (i == 0) {
        m &= ~0xFull;  // leading '/'
      }
      emit(m, i);
    }
    if (i < ulen) {  // overlapped 16-byte tail
      const uint32_t off = ulen - 16;
      const uint8x16_t v0 =
          vld1q_u8(reinterpret_cast<const uint8_t*>(url) + off);
      uint64_t m =
          vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(
                            vreinterpretq_u16_u8(vceqq_u8(v0, slash)), 4)),
                        0);
      m &= ~0ull << ((i - off) * 4);  // drop lanes already processed
      emit(m, off);
    }
  } else {  // short input: scalar scan (<= 15 bytes)
    for (uint32_t i = 1; i < ulen; i++) {
      if (url[i] == '/') {
        if (nseg >= max_fast_path_segments) {
          overflow = true;
          break;
        }
        soff[nseg++] = static_cast<uint16_t>(s);
        s = i + 1;
      }
    }
  }
#else
  for (uint32_t i = 1; i < ulen; i++) {
    if (url[i] == '/') {
      if (nseg >= max_fast_path_segments) {
        overflow = true;
        break;
      }
      soff[nseg++] = static_cast<uint16_t>(s);
      s = i + 1;
    }
  }
#endif
  if (overflow || nseg >= max_fast_path_segments) {
    return 0;
  }
  soff[nseg++] = static_cast<uint16_t>(s);
  soff[nseg] = static_cast<uint16_t>(ulen + 1);  // sentinel
  return nseg;
}

// Static-child dispatch: returns the child ordinal within the node or -1.
// Correctness never depends on the projection: the slot's child is always
// confirmed by a full segment compare, so a bad projection can only cost
// time, never change an answer.
inline int32_t dispatch_static(const compiled_routes& r, const trie_node& nd,
                               const segment_ref& s) noexcept {
  switch (nd.dispatch) {
    case 0:
      return -1;
    case 1: {  // direct: 1-2 masked compares
      const trie_edge* e = r.edges.data() + nd.first_child;
      if (verify_edge(e[0], s, r.blob.data())) {
        return 0;
      }
      if (nd.n_static == 2 && verify_edge(e[1], s, r.blob.data())) {
        return 1;
      }
      return -1;
    }
    case 2: {  // projection: gather -> multiply -> slot -> verify
      const uint64_t proj = project(s.p, s.len, nd.witness_plan);
      const uint8_t ord =
          r.slots[nd.slot_base + slot_of(proj, nd.multiplier, nd.slot_bits)];
      if (ord == 0xFF) {
        return -1;
      }
      return verify_edge(r.edges[static_cast<size_t>(nd.first_child) + ord], s,
                         r.blob.data())
                 ? static_cast<int32_t>(ord)
                 : -1;
    }
    default: {  // linear demotion rung (also carries fanout > 254)
      for (uint32_t j = 0; j < nd.n_static; j++) {
        if (verify_edge(r.edges[static_cast<size_t>(nd.first_child) + j], s,
                        r.blob.data())) {
          return static_cast<int32_t>(j);
        }
      }
      return -1;
    }
  }
}

// Shape-directory probe: tries the groups of this segment count in the
// certified probe order; the first hit is the answer among trie-mode routes
// (the whole-pathname probe already missed, a group miss proves no entry of
// it matches, kept groups are certified wildcard-unoutrankable, and any
// group probed before a lexicographically earlier one is certified
// order-independent). Returns the route index or -1 (the trie decides).
ada_really_inline int32_t shape_lookup(const compiled_routes& r,
                                       const char* url, const uint16_t* soff,
                                       uint32_t nseg) noexcept {
  if (!r.has_shape_tables || nseg > max_trie_pattern_segments) {
    return -1;
  }
  const shape_directory_entry gd = r.group_directory[nseg];
  // Params must bind one non-empty segment; checked only after a verified
  // static hit -- off the common (slot-miss) path.
  const auto params_ok = [&](const shape_group& g) {
    bool ok = true;
    for (uint32_t k = 0; k < g.n_params; k++) {
      ok &= static_cast<uint32_t>(soff[g.param_positions[k] + 1]) -
                soff[g.param_positions[k]] >
            1u;
    }
    return ok;
  };
  for (uint32_t gi = 0; gi < gd.count; gi++) {
    const shape_group& g = r.groups[gd.first + gi];
    if (g.dispatch == 2) [[likely]] {  // projection probe
      // Fixed-shape branchless gather: four independent witness loads at
      // precomputed segment positions.
      const auto feat = [&](uint32_t j) {
        const uint32_t pos = g.witness_positions[j];
        return witness_in_url(url, soff[pos], soff[pos + 1],
                              g.witness_sub_ids[j]);
      };
      const uint64_t proj = pack_projection(feat(0), feat(1), feat(2), feat(3));
      const uint8_t ord =
          r.group_slots[g.slot_base + slot_of(proj, g.multiplier, g.slot_bits)];
      if (ord == 0xFF) {
        continue;
      }
      const static_entry& e = r.group_entries[g.entry_base + ord];
      if (verify_shape(g, e, url, soff, r.blob.data()) && params_ok(g)) {
        return e.route;
      }
    } else {  // direct or linear demotion: verify entries in turn
      for (uint32_t j = 0; j < g.n_entries; j++) {
        const static_entry& e = r.group_entries[g.entry_base + j];
        if (verify_shape(g, e, url, soff, r.blob.data()) && params_ok(g)) {
          return e.route;
        }
      }
    }
  }
  return -1;
}

// ---- builder internals -----------------------------------------------------

// Deterministic constexpr-friendly RNG for the multiplier search
// (splitmix64).
struct splitmix64 {
  uint64_t state;
  constexpr explicit splitmix64(uint64_t seed) noexcept : state(seed) {}
  constexpr uint64_t next() noexcept {
    uint64_t z = (state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  }
};

struct transient_node {  // build-time trie (views into route segment storage)
  std::vector<std::pair<std::string_view, int32_t>> kids{};
  int32_t param = -1;
  int32_t wild_route = -1;
  int32_t terminal = -1;
};

constexpr unsigned ceil_log2(size_t n) noexcept {
  unsigned b = 0;
  while ((size_t{1} << b) < n) {
    b++;
  }
  return b;
}

// Starting table size for n keys: load factor <= ~1/4, loosened as n grows
// so the multiplier search still lands inside the budget.
constexpr unsigned initial_slot_bits(size_t n) noexcept {
  unsigned headroom = 1;
  if (n > 64) {
    headroom = 3;
  } else if (n > 8) {
    headroom = 2;
  }
  return ceil_log2(n) + headroom;
}

bool find_multiplier(const std::vector<uint64_t>& proj, unsigned b0,
                     uint64_t& multiplier_out, uint8_t& bits_out) {
  const size_t n = proj.size();
  for (unsigned b = b0; b <= 12; b++) {
    std::vector<uint32_t> stamp(size_t{1} << b, 0);
    splitmix64 rng(0x14C0FFEEull + b);
    for (uint32_t t = 1; t <= 4000; t++) {
      const uint64_t m = rng.next() | 1;
      bool ok = true;
      for (size_t i = 0; i < n; i++) {
        const uint64_t s = (proj[i] * m) >> (64 - b);
        if (stamp[s] == t) {
          ok = false;
          break;
        }
        stamp[s] = t;
      }
      if (ok) {
        multiplier_out = m;
        bits_out = static_cast<uint8_t>(b);
        return true;
      }
    }
  }
  return false;
}

// Emits a perfect-hash slot table for `proj` at the end of `slots`. Returns
// false if the search failed, in which case nothing was appended and the
// caller demotes that table to a linear scan.
bool emit_slot_table(const std::vector<uint64_t>& proj,
                     std::vector<uint8_t>& slots, uint64_t& multiplier_out,
                     uint8_t& bits_out, uint32_t& base_out) {
  if (!find_multiplier(proj, initial_slot_bits(proj.size()), multiplier_out,
                       bits_out)) {
    return false;
  }
  base_out = static_cast<uint32_t>(slots.size());
  slots.resize(slots.size() + (size_t{1} << bits_out), 0xFF);
  for (size_t i = 0; i < proj.size(); i++) {
    slots[base_out + slot_of(proj[i], multiplier_out, bits_out)] =
        static_cast<uint8_t>(i);
  }
  return true;
}

// Advances `c` to the next k-combination of {0..n-1} in lexicographic
// order; false once the last one has been visited.
template <size_t N>
constexpr bool next_combination(std::array<uint32_t, N>& c, uint32_t k,
                                uint32_t n) noexcept {
  int32_t j = static_cast<int32_t>(k) - 1;
  while (j >= 0 &&
         c[static_cast<uint32_t>(j)] == n - k + static_cast<uint32_t>(j)) {
    j--;
  }
  if (j < 0) {
    return false;
  }
  c[static_cast<uint32_t>(j)]++;
  for (uint32_t t = static_cast<uint32_t>(j) + 1; t < k; t++) {
    c[t] = c[t - 1] + 1;
  }
  return true;
}

// Witness-subset search over the given id alphabet, cost-ordered: fewest
// distinct witness ids first (the length is always packed -- it is free).
// The first injective subset wins.
bool find_witness_plan(
    const std::vector<std::pair<std::string_view, int32_t>>& kids,
    const uint8_t* alphabet, uint32_t n_alpha, uint32_t max_reads,
    uint16_t& plan_out) {
  const size_t n = kids.size();
  auto injective = [&](uint16_t wp) {  // sort + adjacent compare
    std::vector<uint64_t> proj(n);
    for (size_t i = 0; i < n; i++) {
      proj[i] = project(kids[i].first.data(),
                        static_cast<uint32_t>(kids[i].first.size()), wp);
    }
    std::sort(proj.begin(), proj.end());
    for (size_t i = 1; i < n; i++) {
      if (proj[i] == proj[i - 1]) {
        return false;
      }
    }
    return true;
  };
  for (uint32_t k = 1; k <= max_reads && k <= n_alpha; k++) {
    std::array<uint32_t, 3> c{0, 1, 2};
    do {
      uint8_t ids[3] = {0, 0, 0};
      for (uint32_t j = 0; j < k; j++) {
        ids[j] = alphabet[c[j]];
      }
      const uint16_t wp = pack_witness_plan(ids, k, true);
      if (injective(wp)) {
        plan_out = wp;
        return true;
      }
    } while (next_combination(c, k, n_alpha));
  }
  return false;
}

// ---- shape-table build helpers ---------------------------------------------

struct transient_shape_entry {  // static texts of one param route
  std::array<std::string_view, max_shape_statics> statics{};
  int32_t route = -1;
};

struct transient_shape_group {  // one (nseg, param mask) group during build
  uint32_t mask = 0;
  uint32_t n_segments = 0;
  uint32_t n_routes = 0;  // including duplicates
  std::vector<transient_shape_entry> entries{};
};

// Position-reversed mask: ascending revmask == kind-sequence lexicographic
// order within one segment-count class.
constexpr uint32_t revmask(uint32_t mask, uint32_t d) noexcept {
  uint32_t r = 0;
  for (uint32_t j = 0; j < d; j++) {
    if ((mask >> j) & 1u) {
      r |= 1u << (d - 1 - j);
    }
  }
  return r;
}

// Does trie wildcard route W's kind sequence lexicographically precede shape
// mask `mask` in the d-segment class? W precedes iff some position before
// its tail has W static where the mask has a param, all earlier positions
// agreeing in kind.
bool wild_precedes(const route_info& w, uint32_t mask, uint32_t d) noexcept {
  const uint32_t wn = static_cast<uint32_t>(w.segments.size());
  if (wn > d) {
    return false;
  }
  for (uint32_t j = 0; j + 1u < wn; j++) {
    const uint32_t kw = w.segments[j].kind == segment_kind::param ? 1u : 0u;
    const uint32_t ks = (mask >> j) & 1u;
    if (kw != ks) {
      return kw < ks;
    }
  }
  return false;
}

// Could any pathname match wildcard route W and shape-entry route E
// simultaneously? Wherever both have a literal, the texts must agree.
bool wild_compat(const route_info& w, const route_info& e,
                 uint32_t mask) noexcept {
  const uint32_t wn = static_cast<uint32_t>(w.segments.size());
  for (uint32_t j = 0; j + 1u < wn; j++) {
    if (w.segments[j].kind == segment_kind::literal && !((mask >> j) & 1u) &&
        w.segments[j].text != e.segments[j].text) {
      return false;
    }
  }
  return true;
}

// Witness-subset search for one shape group, over the per-static-segment
// alphabet. Preferred features first (first byte, last byte, length of each
// static), deeper bytes after; constant and duplicate feature columns are
// pruned; subsets covering more distinct static segments are preferred
// (they reject more non-matching inputs at the slot).
bool find_shape_plan(const std::vector<transient_shape_entry>& entries,
                     uint32_t n_static, std::array<uint8_t, 4>& ids_out,
                     uint8_t& n_ids_out) {
  const uint32_t n_addr = n_static < 8 ? n_static : 8;  // ordinal << 5 fits
  std::vector<uint8_t> alpha;
  for (uint32_t k = 0; k < n_addr; k++) {
    alpha.push_back(static_cast<uint8_t>((k << 5) | 0));   // first byte
    alpha.push_back(static_cast<uint8_t>((k << 5) | 8));   // last byte
    alpha.push_back(static_cast<uint8_t>((k << 5) | 16));  // length
  }
  constexpr uint8_t deep[14] = {1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15};
  for (uint32_t k = 0; k < n_addr; k++) {
    for (uint8_t id : deep) {
      alpha.push_back(static_cast<uint8_t>((k << 5) | id));
    }
  }

  const size_t n = entries.size();
  // Feature matrix: one column of n bytes per alphabet id.
  std::vector<std::vector<uint8_t>> col(alpha.size(), std::vector<uint8_t>(n));
  for (size_t a = 0; a < alpha.size(); a++) {
    for (size_t i = 0; i < n; i++) {
      const std::string_view sv = entries[i].statics[alpha[a] >> 5];
      col[a][i] = witness(sv.data(), static_cast<uint32_t>(sv.size()),
                          static_cast<uint8_t>(alpha[a] & 31u));
    }
  }
  std::vector<uint32_t> keep;  // preference order kept
  for (size_t a = 0; a < alpha.size(); a++) {
    bool constant = true;
    for (size_t i = 1; i < n && constant; i++) {
      constant = col[a][i] == col[a][0];
    }
    if (constant) {
      continue;
    }
    bool dup = false;
    for (uint32_t kept : keep) {
      bool same = true;
      for (size_t i = 0; i < n && same; i++) {
        same = col[kept][i] == col[a][i];
      }
      if (same) {
        dup = true;
        break;
      }
    }
    if (!dup) {
      keep.push_back(static_cast<uint32_t>(a));
    }
  }
  const uint32_t na = static_cast<uint32_t>(keep.size());
  const uint32_t k = na < 4 ? na : 4;
  if (k == 0) {
    return false;
  }
  const auto injective = [&](const std::array<uint32_t, 4>& c) {
    std::vector<uint64_t> proj(n);
    for (size_t i = 0; i < n; i++) {
      const uint8_t b0 = col[keep[c[0]]][i];
      const uint8_t b1 = col[keep[c[1 < k ? 1 : 0]]][i];
      const uint8_t b2 = col[keep[c[2 < k ? 2 : 0]]][i];
      const uint8_t b3 = col[keep[c[3 < k ? 3 : 0]]][i];
      proj[i] = pack_projection(b0, b1, b2, b3);
    }
    std::sort(proj.begin(), proj.end());
    for (size_t i = 1; i < n; i++) {
      if (proj[i] == proj[i - 1]) {
        return false;
      }
    }
    return true;
  };
  const auto coverage = [&](const std::array<uint32_t, 4>& c) {
    uint32_t segs = 0;
    for (uint32_t j = 0; j < k; j++) {
      segs |= 1u << (alpha[keep[c[j]]] >> 5);
    }
    return static_cast<uint32_t>(std::popcount(segs));
  };
  const uint32_t maxcov = k < n_addr ? k : n_addr;
  for (uint32_t want = maxcov; want >= 1; want--) {  // best coverage first
    std::array<uint32_t, 4> c{0, 1, 2, 3};
    do {
      if (coverage(c) == want && injective(c)) {
        for (uint32_t j = 0; j < 4; j++) {
          ids_out[j] = alpha[keep[c[j < k ? j : 0]]];
        }
        n_ids_out = static_cast<uint8_t>(k);
        return true;
      }
    } while (next_combination(c, k, na));
  }
  return false;
}

// ---- build stages ----------------------------------------------------------

// Segment trie over the trie-mode routes. Priority is resolved here, at
// build, into each node's fixed decision order (static children -> param ->
// wildcard); a DFS in that order returns the match with the
// lexicographically minimal kind sequence. Duplicate patterns collapse onto
// one slot: an occupied slot is never overwritten, so the smallest route
// index survives.
std::vector<transient_node> build_trie(const std::vector<route_info>& routes) {
  std::vector<transient_node> t(1);
  for (size_t i = 0; i < routes.size(); i++) {
    const route_info& rt = routes[i];
    if (rt.mode != route_mode::trie) {
      continue;
    }
    int32_t cur = 0;
    for (const route_segment& ps : rt.segments) {
      if (ps.kind == segment_kind::literal) {
        int32_t nxt = -1;
        for (auto& kv : t[static_cast<size_t>(cur)].kids) {
          if (kv.first == ps.text) {
            nxt = kv.second;
            break;
          }
        }
        if (nxt < 0) {
          nxt = static_cast<int32_t>(t.size());
          t[static_cast<size_t>(cur)].kids.emplace_back(ps.text, nxt);
          t.emplace_back();
        }
        cur = nxt;
      } else if (ps.kind == segment_kind::param) {
        if (t[static_cast<size_t>(cur)].param < 0) {
          t[static_cast<size_t>(cur)].param = static_cast<int32_t>(t.size());
          t.emplace_back();
        }
        cur = t[static_cast<size_t>(cur)].param;
      } else {  // wildcard (classification guarantees final)
        if (t[static_cast<size_t>(cur)].wild_route < 0) {
          t[static_cast<size_t>(cur)].wild_route = static_cast<int32_t>(i);
        }
        cur = -1;
        break;
      }
    }
    if (cur >= 0 && t[static_cast<size_t>(cur)].terminal < 0) {
      t[static_cast<size_t>(cur)].terminal = static_cast<int32_t>(i);
    }
  }
  return t;
}

// Capture positions per route, so extracting params at match time is a
// fixed walk over param_positions.
void compile_route_meta(compiled_routes& r,
                        const std::vector<route_info>& routes) {
  r.routes.resize(routes.size());
  for (size_t i = 0; i < routes.size(); i++) {
    const route_info& rt = routes[i];
    route_meta& rm = r.routes[i];
    if (rt.mode != route_mode::trie) {
      continue;  // meta is only read for trie-answered routes
    }
    rm.n_segments = static_cast<uint8_t>(rt.segments.size());
    for (size_t s = 0; s < rt.segments.size(); s++) {
      if (rt.segments[s].kind == segment_kind::param) {
        // Classification guarantees n_params <= max_captures_per_route for
        // trie-mode routes.
        rm.param_positions[rm.n_params++] = static_cast<uint8_t>(s);
      } else if (rt.segments[s].kind == segment_kind::wildcard) {
        rm.wild = 1;
      }
    }
  }
}

// BFS layout: assign final node ids breadth-first so each node's static
// children occupy a contiguous block of edges[]. Returns the transient-node
// id per final id.
std::vector<int32_t> layout_nodes(compiled_routes& r,
                                  const std::vector<transient_node>& t) {
  std::vector<int32_t> order;  // transient id per final id
  order.push_back(0);
  r.nodes.resize(1);
  for (size_t head = 0; head < order.size(); head++) {
    const transient_node& tn = t[static_cast<size_t>(order[head])];
    trie_node nd{};
    nd.wild_route = tn.wild_route;
    nd.terminal_route = tn.terminal;
    nd.first_child = static_cast<int32_t>(r.edges.size());
    nd.n_static = static_cast<uint16_t>(tn.kids.size());
    const size_t id_base = order.size();  // children take the next BFS ids
    for (size_t ci = 0; ci < tn.kids.size(); ci++) {
      const std::string_view k = tn.kids[ci].first;
      trie_edge e{};
      e.key_length = static_cast<uint16_t>(k.size());
      e.key_offset = static_cast<uint32_t>(r.blob.size());
      r.blob.insert(r.blob.end(), k.begin(), k.end());
      e.prefix = pack_window_le(k.data(), static_cast<uint32_t>(k.size()), 0);
      e.suffix = pack_window_le(
          k.data(), static_cast<uint32_t>(k.size()),
          k.size() >= 8 ? static_cast<uint32_t>(k.size()) - 8 : 0);
      e.node = static_cast<int32_t>(id_base + ci);
      r.edges.push_back(e);
    }
    for (size_t ci = 0; ci < tn.kids.size(); ci++) {
      order.push_back(tn.kids[ci].second);
    }
    if (tn.param >= 0) {
      nd.param_child = static_cast<int32_t>(order.size());
      order.push_back(tn.param);
    }
    nd.has_alternative = (nd.param_child >= 0 || nd.wild_route >= 0) ? 1 : 0;
    r.nodes.resize(order.size());
    r.nodes[head] = nd;
  }
  return order;
}

// Per-node dispatch ladder, chosen by static child count: 0 none, 1-2
// direct compares, 3-16 projection over a restricted alphabet, larger over
// the full alphabet; linear demotion when a search fails or when the fanout
// exceeds max_dispatch_table_entries. Never incorrect, only slower.
void compile_dispatch(compiled_routes& r, const std::vector<transient_node>& t,
                      const std::vector<int32_t>& order) {
  for (size_t ni = 0; ni < r.nodes.size(); ni++) {
    trie_node& nd = r.nodes[ni];
    const transient_node& tn = t[static_cast<size_t>(order[ni])];
    const size_t nk = tn.kids.size();
    if (nk == 0) {
      nd.dispatch = 0;
      continue;
    }
    if (nk <= 2) {
      nd.dispatch = 1;
      continue;
    }
    if (nk > max_dispatch_table_entries) {
      nd.dispatch = 3;  // slot ordinals are 8-bit; linear scan stays correct
      continue;
    }
    const bool small = nk <= 16;
    uint16_t wp = 0;
    bool found;
    if (small) {
      constexpr uint8_t alpha_small[2] = {0, 8};  // s[0], s[len - 1]
      found = find_witness_plan(tn.kids, alpha_small, 2, 2, wp);
    } else {
      found = false;
    }
    if (!found) {  // full alphabet (also the escalation path for 3..16)
      uint8_t alpha_full[16] = {0, 1, 2,  3,  4,  5,  6,  7,
                                8, 9, 10, 11, 12, 13, 14, 15};
      found = find_witness_plan(tn.kids, alpha_full, 16, 3, wp);
    }
    uint64_t multiplier = 0;
    uint8_t bits = 0;
    uint32_t base = 0;
    if (found) {
      std::vector<uint64_t> proj(nk);
      for (size_t i = 0; i < nk; i++) {
        proj[i] = project(tn.kids[i].first.data(),
                          static_cast<uint32_t>(tn.kids[i].first.size()), wp);
      }
      found = emit_slot_table(proj, r.slots, multiplier, bits, base);
    }
    if (!found) {
      nd.dispatch = 3;  // demoted: correct, slower
      continue;
    }
    nd.dispatch = 2;
    nd.witness_plan = wp;
    nd.multiplier = multiplier;
    nd.slot_bits = bits;
    nd.slot_base = base;
  }
}

// The exact pathname a fully static route matches: "/" + segments joined
// with "/" (empty literal segments included).
std::string static_route_key(const route_info& rt) {
  std::string key;
  for (const route_segment& s : rt.segments) {
    key += '/';
    key += s.text;
  }
  return key;
}

// Whole-pathname exact table over the fully static routes (all segments
// literal, any mode but regexp). A hit is the final fast-path answer: a full
// static match has the lexicographically minimal kind sequence. If the table
// cannot be built (too many routes, oversized key, or a failed search), it
// is simply not built and every input walks the trie -- and the fully static
// routes the trie cannot represent stay in the sequential fallback.
void build_static_table(compiled_routes& r, std::vector<route_info>& routes) {
  std::vector<std::string> key_storage;
  std::vector<std::pair<std::string_view, int32_t>> keys;
  std::vector<size_t> covered;  // route indices covered by the table
  key_storage.reserve(routes.size());
  for (size_t i = 0; i < routes.size(); i++) {
    if (routes[i].mode == route_mode::regexp || !routes[i].all_literal) {
      continue;
    }
    std::string key = static_route_key(routes[i]);
    if (key.size() > 65535) {
      return;  // would not fit a 16-bit entry length: no table at all
    }
    covered.push_back(i);
    bool dup = false;
    for (auto& kv : keys) {
      if (kv.first == key) {  // duplicate pattern: smallest index kept
        dup = true;
        break;
      }
    }
    if (!dup) {
      key_storage.push_back(std::move(key));
      keys.emplace_back(key_storage.back(), static_cast<int32_t>(i));
    }
  }
  if (keys.empty() || keys.size() > max_dispatch_table_entries) {
    return;
  }

  uint8_t alphabet[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  uint16_t plan = 0;
  if (!find_witness_plan(keys, alphabet, 16, 3, plan)) {
    return;
  }
  std::vector<uint64_t> proj(keys.size());
  for (size_t k = 0; k < keys.size(); k++) {
    proj[k] = project(keys[k].first.data(),
                      static_cast<uint32_t>(keys[k].first.size()), plan);
  }
  uint64_t multiplier = 0;
  uint8_t bits = 0;
  uint32_t base = 0;  // always 0: static_slots is this table's own vector
  if (!emit_slot_table(proj, r.static_slots, multiplier, bits, base)) {
    return;
  }

  r.has_static_table = 1;
  r.static_witness_plan = plan;
  r.static_multiplier = multiplier;
  r.static_slot_bits = bits;
  for (size_t k = 0; k < keys.size(); k++) {
    static_entry e{};
    e.route = keys[k].second;
    e.length = static_cast<uint16_t>(keys[k].first.size());
    e.offset = static_cast<uint32_t>(r.blob.size());
    r.blob.insert(r.blob.end(), keys[k].first.begin(), keys[k].first.end());
    r.static_entries.push_back(e);
  }
  // A duplicate is covered by its keeper: it matches exactly when the keeper
  // does and can never outrank it.
  for (size_t i : covered) {
    routes[i].covered_by_static_table = true;
  }
}

// Groups trie-mode param routes by shape = (segment count, param-position
// bitmask), ordered by kind sequence. Identical static tuples within a
// shape are duplicates in match behavior; the smallest route index is kept.
std::vector<transient_shape_group> group_by_shape(
    const compiled_routes& r, const std::vector<route_info>& routes) {
  std::vector<transient_shape_group> gs;
  for (size_t i = 0; i < routes.size(); i++) {
    const route_info& rt = routes[i];
    const route_meta& rm = r.routes[i];
    if (rt.mode != route_mode::trie || rm.wild != 0 || rm.n_params == 0) {
      continue;
    }
    uint32_t mask = 0;
    for (uint32_t k = 0; k < rm.n_params; k++) {
      mask |= 1u << rm.param_positions[k];
    }
    const uint32_t nseg = static_cast<uint32_t>(rt.segments.size());
    size_t gi = 0;
    while (gi < gs.size() &&
           !(gs[gi].mask == mask && gs[gi].n_segments == nseg)) {
      gi++;
    }
    if (gi == gs.size()) {
      gs.push_back(transient_shape_group{mask, nseg, 0, {}});
    }
    transient_shape_group& g = gs[gi];
    g.n_routes++;
    transient_shape_entry ent{};
    ent.route = static_cast<int32_t>(i);
    uint32_t n_static = 0;  // == nseg - n_params <= max_shape_statics
    for (const route_segment& s : rt.segments) {
      if (s.kind == segment_kind::literal) {
        ent.statics[n_static++] = s.text;
      }
    }
    bool dup = false;
    for (const auto& prev : g.entries) {
      bool same = true;
      for (uint32_t k = 0; k < n_static && same; k++) {
        same = prev.statics[k] == ent.statics[k];
      }
      if (same) {
        dup = true;
        break;
      }
    }
    if (!dup) {
      g.entries.push_back(ent);
    }
  }
  std::sort(gs.begin(), gs.end(),
            [](const transient_shape_group& a, const transient_shape_group& b) {
              if (a.n_segments != b.n_segments) {
                return a.n_segments < b.n_segments;
              }
              return revmask(a.mask, a.n_segments) <
                     revmask(b.mask, b.n_segments);
            });
  return gs;
}

// Wildcard-outranking truncation: within each segment-count class keep only
// the lexicographic prefix of groups that no trie wildcard route can
// outrank (kind-sequence precedence and static-text co-matchability with
// some entry). Probing must stop at the first non-kept group; everything
// after falls back to the trie, which remains complete.
std::vector<size_t> keep_unoutranked(
    const std::vector<transient_shape_group>& gs,
    const std::vector<route_info>& routes) {
  std::vector<size_t> keep;
  size_t cls = 0;
  while (cls < gs.size()) {
    const uint32_t d = gs[cls].n_segments;
    size_t cls_end = cls;
    while (cls_end < gs.size() && gs[cls_end].n_segments == d) {
      cls_end++;
    }
    bool cut = false;  // once one group of the class is cut, so is the rest
    for (size_t gi = cls; gi < cls_end; gi++) {
      for (size_t wi = 0; wi < routes.size() && !cut; wi++) {
        if (routes[wi].mode != route_mode::trie || !routes[wi].has_wildcard) {
          continue;
        }
        if (!wild_precedes(routes[wi], gs[gi].mask, d)) {
          continue;
        }
        for (const auto& e : gs[gi].entries) {
          if (wild_compat(routes[wi], routes[static_cast<size_t>(e.route)],
                          gs[gi].mask)) {
            cut = true;
            break;
          }
        }
      }
      if (!cut) {
        keep.push_back(gi);
      }
    }
    cls = cls_end;
  }
  return keep;
}

// Entry statics are stored by ordinal; the ordinal of position s is the
// count of static positions below s.
std::string_view static_at(const transient_shape_group& g,
                           const transient_shape_entry& e,
                           uint32_t s) noexcept {
  uint32_t ord = 0;
  for (uint32_t j = 0; j < s; j++) {
    ord += ((g.mask >> j) & 1u) == 0;
  }
  return e.statics[ord];
}

// Order-independence of two groups of one segment-count class: no pathname
// can match an entry of A and an entry of B, which holds iff every entry
// pair conflicts (different text) at some shared static position.
bool groups_independent(const transient_shape_group& a,
                        const transient_shape_group& b) noexcept {
  const uint32_t d = a.n_segments;  // == b.n_segments
  const uint32_t both = a.mask | b.mask;
  for (const transient_shape_entry& ea : a.entries) {
    for (const transient_shape_entry& eb : b.entries) {
      bool conflict = false;
      for (uint32_t s = 0; s < d && !conflict; s++) {
        conflict =
            !((both >> s) & 1u) && static_at(a, ea, s) != static_at(b, eb, s);
      }
      if (!conflict) {
        return false;  // some pathname matches both: order is semantic
      }
    }
  }
  return true;
}

// Probe-order selection: within each class, promote big groups past
// lexicographically earlier ones only where the pair is provably
// order-independent (then no input matches both, so the first hit is the
// same route either way). Greedy selection sort; the remainder is rotated,
// not swapped, so it stays in lexicographic order.
void choose_probe_order(const std::vector<transient_shape_group>& gs,
                        std::vector<size_t>& keep) {
  size_t cls = 0;
  while (cls < keep.size()) {
    size_t cls_end = cls;
    while (cls_end < keep.size() &&
           gs[keep[cls_end]].n_segments == gs[keep[cls]].n_segments) {
      cls_end++;
    }
    for (size_t out = cls; out < cls_end; out++) {
      size_t best = out;
      for (size_t c = out + 1; c < cls_end; c++) {
        if (gs[keep[c]].n_routes <= gs[keep[best]].n_routes) {
          continue;
        }
        bool ok = true;
        for (size_t h = out; h < c && ok; h++) {
          ok = groups_independent(gs[keep[h]], gs[keep[c]]);
        }
        if (ok) {
          best = c;
        }
      }
      if (best != out) {
        const size_t g = keep[best];
        for (size_t j = best; j > out; j--) {
          keep[j] = keep[j - 1];
        }
        keep[out] = g;
      }
    }
    cls = cls_end;
  }
}

// Compiles one kept group: param/static positions and maximal static runs
// from the mask, entry keys (statics joined with '/') into the blob, then
// the dispatch ladder -- direct for <= 2 entries, projection otherwise,
// linear demotion if a search fails.
shape_group compile_shape_group(compiled_routes& r,
                                const transient_shape_group& gt) {
  shape_group g{};
  g.mask = gt.mask;
  g.n_segments = static_cast<uint8_t>(gt.n_segments);
  g.n_entries = static_cast<uint16_t>(gt.entries.size());
  g.entry_base = static_cast<uint32_t>(r.group_entries.size());

  std::array<uint8_t, max_shape_statics> spos{};  // static ordinal -> position
  uint32_t n_static = 0, n_params = 0;
  for (uint32_t s = 0; s < gt.n_segments; s++) {
    if ((gt.mask >> s) & 1u) {
      g.param_positions[n_params++] = static_cast<uint8_t>(s);
    } else {
      spos[n_static++] = static_cast<uint8_t>(s);
    }
  }
  g.n_static = static_cast<uint8_t>(n_static);
  g.n_params = static_cast<uint8_t>(n_params);
  for (uint32_t k = 0, nrun = 0; k < n_static;
       g.n_runs = static_cast<uint8_t>(nrun)) {
    uint32_t end = k;  // maximal run of consecutive static positions
    while (end + 1 < n_static && spos[end + 1] == spos[end] + 1) {
      end++;
    }
    g.run_first[nrun] = spos[k];
    g.run_last[nrun] = spos[end];
    nrun++;
    k = end + 1;
  }

  for (const auto& ent : gt.entries) {
    static_entry e{};
    e.route = ent.route;
    e.offset = static_cast<uint32_t>(r.blob.size());
    uint32_t key_len = 0;
    for (uint32_t k = 0; k < n_static; k++) {
      if (k) {
        r.blob.push_back('/');
        key_len++;
      }
      r.blob.insert(r.blob.end(), ent.statics[k].begin(), ent.statics[k].end());
      key_len += static_cast<uint32_t>(ent.statics[k].size());
    }
    e.length = static_cast<uint16_t>(key_len);
    r.group_entries.push_back(e);
  }

  if (gt.entries.size() <= 2) {
    g.dispatch = 1;  // direct: verify the 1-2 entries in turn
    return g;
  }
  std::array<uint8_t, 4> ids{};
  uint8_t n_ids = 0;
  uint64_t multiplier = 0;
  uint8_t bits = 0;
  bool found = gt.entries.size() <= max_dispatch_table_entries &&
               find_shape_plan(gt.entries, n_static, ids, n_ids);
  if (found) {
    std::vector<uint64_t> proj(gt.entries.size());
    for (size_t ei = 0; ei < gt.entries.size(); ei++) {
      const transient_shape_entry& ent = gt.entries[ei];
      const auto feat = [&](uint8_t id) {
        const std::string_view sv = ent.statics[id >> 5];
        return witness(sv.data(), static_cast<uint32_t>(sv.size()),
                       static_cast<uint8_t>(id & 31u));
      };
      proj[ei] = pack_projection(feat(ids[0]), feat(ids[1]), feat(ids[2]),
                                 feat(ids[3]));
    }
    found = emit_slot_table(proj, r.group_slots, multiplier, bits, g.slot_base);
  }
  if (!found) {
    g.dispatch = 3;  // linear demotion: correct, slower
    return g;
  }
  g.dispatch = 2;
  g.witness_ids = ids;
  for (uint32_t j = 0; j < 4; j++) {  // resolve to absolute segment positions
    g.witness_positions[j] = spos[ids[j] >> 5];
    g.witness_sub_ids[j] = static_cast<uint8_t>(ids[j] & 31u);
  }
  g.multiplier = multiplier;
  g.slot_bits = bits;
  return g;
}

// Shape tables over the trie-mode param routes. Precondition for answering
// from a shape hit: the whole-pathname exact table must cover all fully
// static routes, so that its miss proves no static route matches. If static
// routes exist but that table was not built, shape tables are skipped
// entirely and the trie alone stays correct.
void build_shape_tables(compiled_routes& r,
                        const std::vector<route_info>& routes) {
  r.group_directory.assign(max_trie_pattern_segments + 1,
                           shape_directory_entry{});
  bool any_fully_static = false;
  for (size_t i = 0; i < routes.size() && !any_fully_static; i++) {
    any_fully_static =
        routes[i].mode != route_mode::regexp && routes[i].all_literal;
  }
  if (any_fully_static && !r.has_static_table) {
    return;
  }

  const std::vector<transient_shape_group> gs = group_by_shape(r, routes);
  // Kept groups of one class stay consecutive, which is what lets the
  // directory be a (first, count) pair.
  std::vector<size_t> keep = keep_unoutranked(gs, routes);
  choose_probe_order(gs, keep);
  for (size_t gi : keep) {
    const transient_shape_group& gt = gs[gi];
    const shape_group g = compile_shape_group(r, gt);
    shape_directory_entry& dir = r.group_directory[gt.n_segments];
    if (dir.count == 0) {
      dir.first = static_cast<uint32_t>(r.groups.size());
    }
    dir.count++;
    r.groups.push_back(g);
  }
  r.has_shape_tables = r.groups.empty() ? 0 : 1;
}

// Pure-leaf edge encoding, last: a child that is a pure leaf (terminal
// route only) is encoded as ~route directly in the edge, so the walk
// finishes or dead-ends there without loading the leaf node. -1 keeps
// meaning "absent" for param_child.
void encode_leaf_shortcuts(compiled_routes& r) {
  auto pure_leaf = [&](int32_t ni) {
    const trie_node& nd = r.nodes[static_cast<size_t>(ni)];
    return nd.n_static == 0 && nd.param_child < 0 && nd.wild_route < 0 &&
           nd.terminal_route >= 0;
  };
  for (auto& e : r.edges) {
    if (pure_leaf(e.node)) {
      e.node = -2 - r.nodes[static_cast<size_t>(e.node)].terminal_route;
    }
  }
  for (auto& nd : r.nodes) {
    if (nd.param_child >= 0 && pure_leaf(nd.param_child)) {
      nd.param_child =
          -2 - r.nodes[static_cast<size_t>(nd.param_child)].terminal_route;
    }
  }
}

}  // namespace

// ---- public engine entry points --------------------------------------------

bool classify_parts(const std::vector<url_pattern_part>& parts,
                    std::vector<route_segment>& segments,
                    std::vector<std::string>& group_names) {
  segments.clear();
  group_names.clear();
  bool started = false;        // leading '/' consumed
  bool group_open = false;     // the open segment slot is a group
  bool wildcard_seen = false;  // a "*" segment was consumed (must stay last)
  std::string literal;
  const auto close_segment = [&]() {
    if (!group_open) {
      segments.push_back(route_segment{segment_kind::literal, literal});
    }
    literal.clear();
    group_open = false;
  };
  const auto process_text = [&](std::string_view text) {
    for (const char c : text) {
      if (wildcard_seen) {
        return false;  // nothing may follow a "*" segment
      }
      if (c == '/') {
        if (!started) {
          started = true;
        } else {
          close_segment();
        }
      } else {
        if (!started || group_open) {
          return false;  // text before '/', or suffix text after a group
        }
        literal += c;
      }
    }
    return true;
  };
  for (const url_pattern_part& part : parts) {
    if (part.type == url_pattern_part_type::FIXED_TEXT &&
        part.modifier == url_pattern_part_modifier::none) {
      if (!process_text(part.prefix) || !process_text(part.value) ||
          !process_text(part.suffix)) {
        return false;
      }
    } else if ((part.type == url_pattern_part_type::SEGMENT_WILDCARD ||
                part.type == url_pattern_part_type::FULL_WILDCARD) &&
               part.modifier == url_pattern_part_modifier::none &&
               part.suffix.empty()) {
      if (wildcard_seen) {
        return false;
      }
      if (part.prefix == "/") {
        if (!started) {
          started = true;
        } else {
          close_segment();
        }
      } else if (part.prefix.empty()) {
        // The group must occupy a whole, freshly opened segment slot.
        if (!started || group_open || !literal.empty()) {
          return false;
        }
      } else {
        return false;  // group not aligned on a '/' boundary
      }
      const bool is_wildcard =
          part.type == url_pattern_part_type::FULL_WILDCARD;
      segments.push_back(route_segment{
          is_wildcard ? segment_kind::wildcard : segment_kind::param,
          part.name});
      group_names.push_back(part.name);
      group_open = true;
      wildcard_seen = is_wildcard;
    } else {
      return false;  // regexp group or a "?" / "+" / "*" modifier
    }
  }
  if (!started) {
    // Only the empty pattern (zero parts) is representable without a leading
    // '/': it matches exactly the empty pathname.
    return parts.empty();
  }
  close_segment();
  return true;
}

void compute_kind_sequence(route_info& route) noexcept {
  uint64_t seq = 0;
  const size_t n = route.segments.size();
  for (size_t j = 0; j < n && j < 32; j++) {
    seq |= static_cast<uint64_t>(route.segments[j].kind) << (62 - 2 * j);
  }
  route.kind_sequence = seq;
  route.kind_length = static_cast<uint8_t>(n < 255 ? n : 255);
}

void finalize_route(route_info& route) noexcept {
  compute_kind_sequence(route);
  route.all_literal = true;
  route.has_wildcard = false;
  size_t n_params = 0;
  bool empty_literal = false;
  for (const route_segment& s : route.segments) {
    if (s.kind == segment_kind::literal) {
      empty_literal |= s.text.empty();
    } else {
      route.all_literal = false;
      if (s.kind == segment_kind::param) {
        n_params++;
      } else {
        route.has_wildcard = true;
      }
    }
  }
  const size_t n_captures = n_params + (route.has_wildcard ? 1 : 0);
  const bool trie_safe = !route.segments.empty() && !empty_literal &&
                         route.segments.size() <= max_trie_pattern_segments &&
                         n_captures <= max_captures_per_route;
  route.mode = trie_safe ? route_mode::trie : route_mode::sequential;
}

void approximate_kind_sequence(const std::vector<url_pattern_part>& parts,
                               route_info& route) {
  std::vector<uint8_t> kinds;
  bool started = false;
  bool open = false;
  uint8_t current = 0;
  const auto close = [&]() {
    if (open) {
      kinds.push_back(current);
      open = false;
      current = 0;
    }
  };
  const auto process_text = [&](std::string_view text) {
    for (const char c : text) {
      if (c == '/') {
        if (started) {
          close();
        }
        started = true;
        open = true;
        current = 0;
      } else {
        if (!started) {
          started = true;
        }
        if (!open) {
          open = true;
          current = 0;
        }
      }
    }
  };
  const auto add_group = [&](uint8_t kind) {
    if (!open) {
      started = true;
      open = true;
      current = 0;
    }
    current = current < kind ? kind : current;
  };
  for (const url_pattern_part& part : parts) {
    if (part.type == url_pattern_part_type::FULL_WILDCARD ||
        part.modifier != url_pattern_part_modifier::none) {
      // A greedy or modified group can span segments: treat the rest of the
      // route as a wildcard tail and stop.
      close();
      kinds.push_back(2);
      break;
    }
    if (part.type == url_pattern_part_type::FIXED_TEXT) {
      process_text(part.value);
    } else {  // SEGMENT_WILDCARD or REGEXP, modifier none
      process_text(part.prefix);
      add_group(1);
      process_text(part.suffix);
    }
  }
  close();
  uint64_t seq = 0;
  for (size_t j = 0; j < kinds.size() && j < 32; j++) {
    seq |= static_cast<uint64_t>(kinds[j]) << (62 - 2 * j);
  }
  route.kind_sequence = seq;
  route.kind_length =
      static_cast<uint8_t>(kinds.size() < 255 ? kinds.size() : 255);
  route.mode = route_mode::regexp;
  route.all_literal = false;
}

compiled_routes compile_route_set(std::vector<route_info>& routes) {
  compiled_routes r{};
  const std::vector<transient_node> t = build_trie(routes);
  compile_route_meta(r, routes);
  const std::vector<int32_t> order = layout_nodes(r, t);
  compile_dispatch(r, t, order);
  build_static_table(r, routes);
  build_shape_tables(r, routes);  // gated on the exact table's completeness
  encode_leaf_shortcuts(r);       // last: must not confuse the stages above
  return r;
}

engine_result match_compiled(const compiled_routes& r,
                             std::string_view pathname) noexcept {
  engine_result out{};
  if (pathname.empty() || pathname[0] != '/' ||
      pathname.size() > max_fast_path_pathname_length) {
    out.within_fast_path = false;  // the sequential fallback decides
    return out;
  }
  const char* url = pathname.data();
  const uint32_t ulen = static_cast<uint32_t>(pathname.size());

  // Whole-pathname exact probe first (fully static routes; one projection,
  // one slot, one verify). A hit is the final engine answer; a miss falls
  // through. No segmentation is needed on this path.
  if (r.has_static_table) {
    const uint64_t proj = project(url, ulen, r.static_witness_plan);
    const uint8_t ord =
        r.static_slots[slot_of(proj, r.static_multiplier, r.static_slot_bits)];
    if (ord != 0xFF) {
      const static_entry& e = r.static_entries[ord];
      if (e.length == ulen && eq_bytes(url, r.blob.data() + e.offset, ulen)) {
        out.route = e.route;
        return out;
      }
    }
  }

  // Segment scan; overflow means the input is beyond the fast path.
  uint16_t soff[max_fast_path_segments + 1];
  const uint32_t nseg = scan_segments(url, ulen, soff);
  if (nseg == 0) {
    out.within_fast_path = false;
    return out;
  }
  const auto seg_len = [&](uint32_t i) {
    return static_cast<uint32_t>(soff[i + 1]) - soff[i] - 1u;
  };

  // Shape-directory probe: whole-route witness dispatch for the param
  // routes of this segment count, tried before the trie walk. A hit is
  // final among trie routes; a miss falls through to the walk, which
  // remains complete.
  {
    const int32_t shape_route = shape_lookup(r, url, soff, nseg);
    if (shape_route >= 0) {
      out.route = shape_route;
      const route_meta& rm = r.routes[static_cast<size_t>(shape_route)];
      for (uint32_t k = 0; k < rm.n_params; k++) {
        const uint32_t p = rm.param_positions[k];
        out.captures[k] = {soff[p], seg_len(p)};
      }
      out.capture_count = rm.n_params;
      return out;
    }
  }

  // Window-safety contract for the trie walk: verify_edge reads whole
  // 8-byte windows at a segment's start (and at start + len - 8), so a
  // segment at offset `off` needs off + 8 <= ulen. That can fail only when
  // the final segment is shorter than 8 bytes; exactly then, materialize a
  // 16-byte zero-padded copy of the input's last 8 bytes and point the
  // affected segments' window base into it. The input itself is never
  // copied.
  char endpad[16] = {};
  uint32_t tail_off = 0;
  if (ulen - soff[nseg - 1] < 8) {
    if (ulen >= 8) {  // one unaligned load, not a byte loop
      const uint64_t t8 = load8_le(url + (ulen - 8));
      tail_off = ulen - 8;
      std::memcpy(endpad, &t8, 8);
    } else {
      for (uint32_t j = 0; j < ulen; j++) {
        endpad[j] = url[j];
      }
    }
  }
  const auto seg_ref = [&](uint32_t i) {
    const uint32_t off = soff[i];
    const char* p = url + off;
    const char* vp = (off + 8 <= ulen) ? p : endpad + (off - tail_off);
    return segment_ref{p, vp, seg_len(i)};
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
    const trie_node& nd = r.nodes[static_cast<size_t>(node)];
    if (alt == alt_static) {
      if (i == nseg) {
        if (nd.terminal_route >= 0) {
          route = nd.terminal_route;
          break;
        }
        alt = alt_none;
      } else {
        const int32_t ord = dispatch_static(r, nd, seg_ref(i));
        if (ord >= 0) {
          const int32_t nxt = r.edges[static_cast<size_t>(nd.first_child) +
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
      if (nd.wild_route >= 0) {
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
    const route_meta& rm = r.routes[static_cast<size_t>(route)];
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
  return out;
}

bool match_route_sequential(const route_info& route, std::string_view pathname,
                            engine_result& result) noexcept {
  result.capture_count = 0;
  result.captures_truncated = false;
  const auto& segs = route.segments;
  if (segs.empty()) {
    return pathname.empty();  // the empty pattern matches only ""
  }
  if (pathname.empty() || pathname[0] != '/') {
    return false;
  }
  const size_t n_pattern = segs.size();
  const bool wild = route.has_wildcard;  // wildcard is always the last segment
  const size_t n_fixed = wild ? n_pattern - 1 : n_pattern;
  uint32_t total_captures = 0;
  const auto add_capture = [&](size_t offset, size_t length) {
    if (total_captures < max_captures_per_route) {
      result.captures[total_captures] = {static_cast<uint32_t>(offset),
                                         static_cast<uint32_t>(length)};
    } else {
      result.captures_truncated = true;
    }
    total_captures++;
  };
  size_t seg_start = 1;
  for (size_t si = 0; si < n_fixed; si++) {
    if (seg_start > pathname.size()) {
      return false;  // the input has fewer segments than the pattern
    }
    const size_t slash = pathname.find('/', seg_start);
    const size_t seg_end =
        slash == std::string_view::npos ? pathname.size() : slash;
    // seg_start <= pathname.size() was checked above, so this is in range
    // (spelled without substr to keep the function provably non-throwing).
    const std::string_view s(pathname.data() + seg_start, seg_end - seg_start);
    if (segs[si].kind == segment_kind::literal) {
      if (s != segs[si].text) {
        return false;
      }
    } else {  // param: binds one non-empty segment
      if (s.empty()) {
        return false;
      }
      add_capture(seg_start, s.size());
    }
    seg_start = seg_end + 1;
  }
  if (wild) {
    if (seg_start > pathname.size()) {
      return false;  // the wildcard still needs its (possibly empty) segment
    }
    add_capture(seg_start, pathname.size() - seg_start);
  } else if (seg_start != pathname.size() + 1) {
    return false;  // the input has more segments than the pattern
  }
  result.capture_count = total_captures < max_captures_per_route
                             ? total_captures
                             : max_captures_per_route;
  return true;
}

}  // namespace ada::url_pattern_list_helpers
#endif  // ADA_INCLUDE_URL_PATTERN
