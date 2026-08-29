/**
 * @file url_pattern_list.cpp
 * @brief Route-set compiler backing ada::url_pattern_list.
 *
 * The provider-independent build side: classification of URLPattern part
 * lists into pattern segments, the compiler (segment trie, per-node dispatch,
 * auxiliary-route pruning), the arena packing, and the sequential reference
 * matcher used beyond the fast-path limits. The matcher itself is inline in
 * url_pattern_list-inl.h.
 *
 * Every dispatch decision is made at build time so that the per-request
 * residual is a segment scan and a trie walk with bounded backtracking.
 * Offline searches (witness plans, perfect multipliers) that fail demote the
 * affected node to a linear scan: slower, never incorrect.
 */
#include "ada.h"
#include "url_pattern_list_compiler.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <span>

#if ADA_INCLUDE_URL_PATTERN

namespace ada::url_pattern_list_compiler {

namespace {

using url_pattern_list_detail::compiled_routes;
using url_pattern_list_detail::edge_record;
using url_pattern_list_detail::hash_record;
using url_pattern_list_detail::node_record;
using url_pattern_list_detail::route_mode;
using url_pattern_list_detail::route_record;
using url_pattern_list_detail::segment_record;
using url_pattern_list_limits::max_captures_per_route;
using url_pattern_list_limits::max_trie_pattern_segments;

// The tables under construction, one vector per section; packed into the
// single arena of compiled_routes at the end of the build.
struct builder_tables {
  std::vector<node_record> nodes{};
  std::vector<hash_record> hashes{};
  std::vector<edge_record> edges{};
  std::vector<uint8_t> slots{};
  std::vector<char> blob{};
  std::vector<route_record> routes{};
  std::vector<segment_record> segments{};
  std::vector<uint32_t> aux{};
  std::vector<uint16_t> root_index{};
  uint32_t n_aux_all = 0;
};

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

// Deterministic RNG for the multiplier search (splitmix64).
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
    slots[base_out +
          url_pattern_list_detail::slot_of(proj[i], multiplier_out, bits_out)] =
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
      proj[i] = url_pattern_list_detail::project(
          kids[i].first.data(), static_cast<uint32_t>(kids[i].first.size()),
          wp);
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
  // The root's children are sorted by first byte so that the first-byte
  // index can address each run of same-byte children as one contiguous
  // block of edges.
  std::stable_sort(
      t[0].kids.begin(), t[0].kids.end(), [](const auto& a, const auto& b) {
        const int ka = a.first.empty() ? -1 : static_cast<uint8_t>(a.first[0]);
        const int kb = b.first.empty() ? -1 : static_cast<uint8_t>(b.first[0]);
        return ka < kb;
      });
  return t;
}

// Per-route records: priority data, capture positions (so extracting params
// at match time is a fixed walk over param_positions), regexp ordinals.
void compile_route_records(builder_tables& r,
                           const std::vector<route_info>& routes) {
  r.routes.resize(routes.size());
  int32_t n_regexp = 0;
  for (size_t i = 0; i < routes.size(); i++) {
    const route_info& rt = routes[i];
    route_record& rm = r.routes[i];
    rm.kind_sequence = rt.kind_sequence;
    rm.kind_length = rt.kind_length;
    rm.mode = rt.mode;
    rm.wild = rt.has_wildcard ? 1 : 0;
    if (rt.mode == route_mode::regexp) {
      rm.regexp_component = n_regexp++;
      continue;
    }
    if (rt.mode != route_mode::trie) {
      continue;  // capture positions are only read for trie-answered routes
    }
    for (size_t s = 0; s < rt.segments.size(); s++) {
      if (rt.segments[s].kind == segment_kind::param) {
        // Classification guarantees n_params <= max_captures_per_route for
        // trie-mode routes.
        rm.param_positions[rm.n_params++] = static_cast<uint8_t>(s);
      }
    }
  }
}

// BFS layout: assign final node ids breadth-first so each node's static
// children occupy a contiguous block of edges[]. Returns the transient-node
// id per final id.
std::vector<int32_t> layout_nodes(builder_tables& r,
                                  const std::vector<transient_node>& t) {
  std::vector<int32_t> order;  // transient id per final id
  order.push_back(0);
  r.nodes.resize(1);
  for (size_t head = 0; head < order.size(); head++) {
    const transient_node& tn = t[static_cast<size_t>(order[head])];
    node_record nd{};
    nd.wild_route = tn.wild_route;
    nd.terminal_route = tn.terminal;
    nd.first_child = static_cast<int32_t>(r.edges.size());
    nd.n_static = static_cast<uint16_t>(tn.kids.size());
    const size_t id_base = order.size();  // children take the next BFS ids
    for (size_t ci = 0; ci < tn.kids.size(); ci++) {
      const std::string_view k = tn.kids[ci].first;
      edge_record e{};
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

// Root first-byte index: a 256-entry table from the first byte of the
// input's first segment to the first root child starting with it (the
// children are sorted by first byte). Built for a root with at least three
// children; a run of same-byte children longer than max_direct_children, or
// an empty key, falls back to the regular ladder. Returns true when the
// index was emitted.
bool build_root_index(builder_tables& r, const transient_node& root) {
  const size_t nk = root.kids.size();
  if (nk < 3) {
    return false;
  }
  std::array<uint16_t, 256> index{};
  index.fill(0xFFFF);
  std::array<uint32_t, 256> run{};
  for (size_t ci = 0; ci < nk; ci++) {
    if (root.kids[ci].first.empty()) {
      return false;  // an empty key has no first byte: regular ladder
    }
    const uint8_t b = static_cast<uint8_t>(root.kids[ci].first[0]);
    if (index[b] == 0xFFFF) {
      index[b] = static_cast<uint16_t>(ci);
    }
    if (++run[b] > max_direct_children) {
      return false;
    }
  }
  r.root_index.assign(index.begin(), index.end());
  return true;
}

// Per-node dispatch ladder, chosen by static child count: 0 none, up to
// max_direct_children direct compares, then projection over a restricted
// alphabet (escalating to the full alphabet); linear demotion when a search
// fails or when the fanout exceeds max_dispatch_table_entries. The root
// gets the first-byte index when its fanout allows. Never incorrect, only
// slower.
void compile_dispatch(builder_tables& r, const std::vector<transient_node>& t,
                      const std::vector<int32_t>& order) {
  for (size_t ni = 0; ni < r.nodes.size(); ni++) {
    node_record& nd = r.nodes[ni];
    const transient_node& tn = t[static_cast<size_t>(order[ni])];
    const size_t nk = tn.kids.size();
    if (nk == 0) {
      nd.dispatch = 0;
      continue;
    }
    if (ni == 0 && build_root_index(r, tn)) {
      nd.dispatch = 4;
      continue;
    }
    if (nk <= max_direct_children) {
      nd.dispatch = 1;
      continue;
    }
    if (nk > max_dispatch_table_entries) {
      nd.dispatch = 3;  // slot ordinals are 8-bit; linear scan stays correct
      continue;
    }
    uint16_t wp = 0;
    bool found = false;
    if (nk <= 16) {
      constexpr uint8_t alpha_small[2] = {0, 8};  // s[0], s[len - 1]
      found = find_witness_plan(tn.kids, alpha_small, 2, 2, wp);
    }
    if (!found) {  // full alphabet (also the escalation path for <= 16)
      uint8_t alpha_full[16] = {0, 1, 2,  3,  4,  5,  6,  7,
                                8, 9, 10, 11, 12, 13, 14, 15};
      found = find_witness_plan(tn.kids, alpha_full, 16, 3, wp);
    }
    hash_record h{};
    if (found) {
      std::vector<uint64_t> proj(nk);
      for (size_t i = 0; i < nk; i++) {
        proj[i] = url_pattern_list_detail::project(
            tn.kids[i].first.data(),
            static_cast<uint32_t>(tn.kids[i].first.size()), wp);
      }
      found = emit_slot_table(proj, r.slots, h.multiplier, h.slot_bits,
                              h.slot_base);
    }
    if (!found) {
      nd.dispatch = 3;  // demoted: correct, slower
      continue;
    }
    nd.dispatch = 2;
    h.witness_plan = wp;
    nd.hash_index = static_cast<uint32_t>(r.hashes.size());
    r.hashes.push_back(h);
  }
}

// Pure-leaf edge encoding, last: a child that is a pure leaf (terminal
// route only) is encoded as -2 - route directly in the edge, so the walk
// finishes or dead-ends there without loading the leaf node. -1 keeps
// meaning "absent" for param_child.
void encode_leaf_shortcuts(builder_tables& r) {
  auto pure_leaf = [&](int32_t ni) {
    const node_record& nd = r.nodes[static_cast<size_t>(ni)];
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

// Segment table: every non-regexp route's segments (kind plus literal text
// in the blob), so the sequential fallback beyond the fast-path limits can
// match any route without the compiler's types; for regexp routes, the
// anchored literal prefix the matcher checks before running the provider.
void build_segment_table(builder_tables& r,
                         const std::vector<route_info>& routes) {
  for (size_t i = 0; i < routes.size(); i++) {
    const route_info& rt = routes[i];
    route_record& rm = r.routes[i];
    rm.segment_first = static_cast<uint32_t>(r.segments.size());
    rm.segment_count = static_cast<uint32_t>(rt.segments.size());
    for (const route_segment& s : rt.segments) {
      segment_record sr{};
      sr.kind = static_cast<uint8_t>(s.kind);
      if (s.kind == segment_kind::literal) {
        sr.text_offset = static_cast<uint32_t>(r.blob.size());
        sr.text_length = static_cast<uint32_t>(s.text.size());
        r.blob.insert(r.blob.end(), s.text.begin(), s.text.end());
      }
      r.segments.push_back(sr);
    }
  }
}

// Could some pathname match both a fast-path route `w` (full segment
// information) and route `c`? Conservative: true unless a literal conflict
// or a segment-count conflict proves otherwise. For a regexp-mode `c`,
// segments are what approximate_kind_sequence could certify (see there);
// has_wildcard means the input needs at least segments.size() segments
// rather than exactly that many.
bool co_matchable(const route_info& w, const route_info& c) noexcept {
  const bool c_regexp = c.mode == route_mode::regexp;
  const size_t wn = w.segments.size();
  const size_t cn = c.segments.size();
  constexpr size_t unbounded = ~size_t{0};
  // Segment counts each route accepts: [min, max].
  const size_t w_max = w.has_wildcard ? unbounded : wn;
  const size_t c_max = c.has_wildcard ? unbounded : cn;
  if ((wn > cn ? wn : cn) > (w_max < c_max ? w_max : c_max)) {
    return false;
  }
  // Positions both routes constrain (a safe wildcard segment constrains
  // nothing; a regexp route's segments are all constraining).
  const size_t w_fixed = w.has_wildcard ? wn - 1 : wn;
  const size_t c_fixed = (!c_regexp && c.has_wildcard) ? cn - 1 : cn;
  const size_t upto = w_fixed < c_fixed ? w_fixed : c_fixed;
  for (size_t j = 0; j < upto; j++) {
    const route_segment& ws = w.segments[j];
    const route_segment& cs = c.segments[j];
    if (ws.kind == segment_kind::literal && cs.kind == segment_kind::literal) {
      if (ws.text != cs.text) {
        return false;
      }
    } else if (ws.kind == segment_kind::literal &&
               cs.kind == segment_kind::param) {
      if (ws.text.empty()) {
        return false;  // params never bind an empty segment
      }
    } else if (ws.kind == segment_kind::param &&
               cs.kind == segment_kind::literal) {
      if (cs.text.empty()) {
        return false;
      }
    }
  }
  return true;
}

// Auxiliary routes: those the trie cannot answer for (regexp mode and
// sequential mode), in insertion order, followed by one challenger range per
// trie route: the auxiliary routes that outrank it AND could match the same
// input. After a fast-path hit only the winner's challengers are tested
// (usually none).
void build_aux_table(builder_tables& r, const std::vector<route_info>& routes) {
  std::vector<uint32_t> aux_all;
  for (size_t i = 0; i < routes.size(); i++) {
    if (routes[i].mode != route_mode::trie) {
      aux_all.push_back(static_cast<uint32_t>(i));
    }
  }
  r.aux = aux_all;
  r.n_aux_all = static_cast<uint32_t>(aux_all.size());
  for (size_t w = 0; w < routes.size(); w++) {
    const route_info& winner = routes[w];
    if (winner.mode != route_mode::trie) {
      continue;  // never a fast-path winner
    }
    route_record& rm = r.routes[w];
    rm.challenger_first = static_cast<uint32_t>(r.aux.size());
    for (const uint32_t c : aux_all) {
      if (route_outranks(routes[c], c, winner, w) &&
          co_matchable(winner, routes[c])) {
        r.aux.push_back(c);
      }
    }
    rm.challenger_count =
        static_cast<uint32_t>(r.aux.size()) - rm.challenger_first;
  }
}

// Packs every table into one arena, each section 8-byte aligned, and
// records the section offsets. The blob gets 8 bytes of zero padding so
// short key windows can always be loaded whole.
compiled_routes pack_arena(builder_tables& r) {
  compiled_routes out{};
  r.blob.insert(r.blob.end(), 8, '\0');
  size_t total = 0;
  const auto reserve = [&](size_t bytes) {
    const size_t offset = total;
    total += (bytes + 7) & ~size_t{7};
    return static_cast<uint32_t>(offset);
  };
  const auto bytes_of = [](const auto& v) { return v.size() * sizeof(v[0]); };
  out.nodes_offset = reserve(bytes_of(r.nodes));
  out.hashes_offset = reserve(bytes_of(r.hashes));
  out.edges_offset = reserve(bytes_of(r.edges));
  out.slots_offset = reserve(bytes_of(r.slots));
  out.blob_offset = reserve(bytes_of(r.blob));
  out.routes_offset = reserve(bytes_of(r.routes));
  out.segments_offset = reserve(bytes_of(r.segments));
  out.aux_offset = reserve(bytes_of(r.aux));
  out.root_index_offset = reserve(bytes_of(r.root_index));
  out.arena.assign(total, 0);
  const auto place = [&](uint32_t offset, const auto& v) {
    if (!v.empty()) {
      std::memcpy(out.arena.data() + offset, v.data(), v.size() * sizeof(v[0]));
    }
  };
  place(out.nodes_offset, r.nodes);
  place(out.hashes_offset, r.hashes);
  place(out.edges_offset, r.edges);
  place(out.slots_offset, r.slots);
  place(out.blob_offset, r.blob);
  place(out.routes_offset, r.routes);
  place(out.segments_offset, r.segments);
  place(out.aux_offset, r.aux);
  place(out.root_index_offset, r.root_index);
  out.n_routes = static_cast<uint32_t>(r.routes.size());
  out.n_aux_all = r.n_aux_all;
  return out;
}

// Fills route.kind_sequence / kind_length from route.segments.
void compute_kind_sequence(route_info& route) noexcept {
  uint64_t seq = 0;
  const size_t n = route.segments.size();
  for (size_t j = 0; j < n && j < 32; j++) {
    seq |= static_cast<uint64_t>(route.segments[j].kind) << (62 - 2 * j);
  }
  route.kind_sequence = seq;
  route.kind_length = static_cast<uint8_t>(n < 255 ? n : 255);
}

}  // namespace

// ---- compiler entry points -------------------------------------------------

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

void finalize_route(route_info& route) noexcept {
  compute_kind_sequence(route);
  route.all_literal = true;
  route.has_wildcard = false;
  size_t n_params = 0;
  for (const route_segment& s : route.segments) {
    if (s.kind != segment_kind::literal) {
      route.all_literal = false;
      if (s.kind == segment_kind::param) {
        n_params++;
      } else {
        route.has_wildcard = true;
      }
    }
  }
  const size_t n_captures = n_params + (route.has_wildcard ? 1 : 0);
  const bool trie_safe = !route.segments.empty() &&
                         route.segments.size() <= max_trie_pattern_segments &&
                         n_captures <= max_captures_per_route;
  route.mode = trie_safe ? route_mode::trie : route_mode::sequential;
}

void approximate_kind_sequence(const std::vector<url_pattern_part>& parts,
                               route_info& route) {
  std::vector<uint8_t> kinds;
  // The route's segment shape, as far as it is known: literal segments carry
  // their text, opaque ones (a ":name" group, alone or mixed with text) are
  // params. Exact while every group is a ":name" segment wildcard, which
  // cannot match '/': then the segment count and every literal position are
  // certain. A custom "(...)" group, a "*" or a modifier can span segments,
  // so from there on nothing is known and only the anchored literal prefix
  // before it is kept.
  std::vector<route_segment> shape;
  std::string literal;
  bool started = false;
  bool open = false;
  bool leading_slash = false;  // the pattern is anchored at a '/'
  bool exact = true;           // no part can span a segment boundary
  bool tail_known = true;      // segments after the last closed one are known
  uint8_t current = 0;
  // Closes the open segment; `complete` is true only when a '/' of fixed
  // text closed it, i.e. the segment is exactly what was accumulated.
  const auto close = [&](bool complete) {
    if (open) {
      kinds.push_back(current);
      if (complete || exact) {
        shape.push_back(current == 0
                            ? route_segment{segment_kind::literal, literal}
                            : route_segment{segment_kind::param, {}});
      } else {
        tail_known = false;
      }
      open = false;
      current = 0;
    }
    literal.clear();
  };
  const auto process_text = [&](std::string_view text) {
    for (const char c : text) {
      if (c == '/') {
        if (started) {
          close(true);
        } else {
          leading_slash = true;
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
        literal += c;
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
      // route as a wildcard tail and stop. A "/" prefix still closes the
      // previous segment as a whole one.
      exact = false;
      close(part.prefix == "/");
      tail_known = false;
      kinds.push_back(2);
      break;
    }
    if (part.type == url_pattern_part_type::FIXED_TEXT) {
      process_text(part.value);
    } else {  // SEGMENT_WILDCARD or REGEXP, modifier none
      if (part.type == url_pattern_part_type::REGEXP) {
        exact = false;  // a custom group may match '/'
      }
      process_text(part.prefix);
      add_group(1);
      process_text(part.suffix);
    }
  }
  close(exact);
  uint64_t seq = 0;
  for (size_t j = 0; j < kinds.size() && j < 32; j++) {
    seq |= static_cast<uint64_t>(kinds[j]) << (62 - 2 * j);
  }
  route.kind_sequence = seq;
  route.kind_length =
      static_cast<uint8_t>(kinds.size() < 255 ? kinds.size() : 255);
  route.mode = route_mode::regexp;
  route.all_literal = false;
  route.segments.clear();
  if (!leading_slash) {
    // Not anchored at '/': nothing about the segments is known.
    route.has_wildcard = true;
    return;
  }
  // has_wildcard here means "the tail is unconstrained": the input needs at
  // least segments.size() segments; otherwise exactly that many.
  route.has_wildcard = !(exact && tail_known);
  if (route.has_wildcard) {
    // Keep only the anchored literal prefix.
    size_t n_prefix = 0;
    while (n_prefix < shape.size() &&
           shape[n_prefix].kind == segment_kind::literal) {
      n_prefix++;
    }
    shape.resize(n_prefix);
  }
  route.segments = std::move(shape);
}

compiled_routes compile_route_set(std::vector<route_info>& routes) {
  builder_tables r{};
  const std::vector<transient_node> t = build_trie(routes);
  compile_route_records(r, routes);
  const std::vector<int32_t> order = layout_nodes(r, t);
  compile_dispatch(r, t, order);
  encode_leaf_shortcuts(r);  // last: must not confuse the stages above
  build_segment_table(r, routes);
  build_aux_table(r, routes);
  compiled_routes out = pack_arena(r);
  out.group_names.resize(routes.size());
  for (size_t i = 0; i < routes.size(); i++) {
    if (routes[i].mode != route_mode::regexp) {
      out.group_names[i] = routes[i].group_names;
    }
  }
  return out;
}

}  // namespace ada::url_pattern_list_compiler

namespace ada::url_pattern_list_detail {

tl::expected<compiled_routes, errors> compile_pathname_patterns(
    std::span<const std::string> patterns, bool ignore_case) {
  namespace compiler = url_pattern_list_compiler;
  std::vector<compiler::route_info> routes;
  routes.reserve(patterns.size());
  for (const std::string& pattern : patterns) {
    // The pattern side goes through ada's own URLPattern machinery: the
    // pattern parser tokenizes and canonicalizes exactly as a URLPattern
    // pathname component would.
    auto options = url_pattern_compile_component_options::PATHNAME;
    auto part_list = url_pattern_helpers::parse_pattern_string(
        pattern, options, url_pattern_helpers::canonicalize_pathname);
    if (!part_list) {
      return tl::unexpected(part_list.error());
    }
    compiler::route_info route{};
    if (compiler::classify_parts(*part_list, route.segments,
                                 route.group_names)) {
      compiler::finalize_route(route);
    } else {
      // The pattern needs URLPattern regexp semantics: the caller compiles
      // it as a pathname component through the provider; it participates
      // in the priority order via its approximated kind sequence.
      compiler::approximate_kind_sequence(*part_list, route);
    }
    if (ignore_case) {
      // The compiled literals are ASCII-folded; the matcher folds the input
      // the same way.
      for (compiler::route_segment& s : route.segments) {
        if (s.kind == compiler::segment_kind::literal) {
          ascii_fold(s.text.data(), static_cast<uint32_t>(s.text.size()),
                     s.text.data());
        }
      }
    }
    routes.push_back(std::move(route));
  }
  compiled_routes compiled = compiler::compile_route_set(routes);
  compiled.ignore_case = ignore_case ? 1 : 0;
  return compiled;
}

namespace {

// Literal-segment compare against the blob, folding the input on request
// (the blob text is already folded).
bool literal_equals(std::string_view s, const char* text, uint32_t length,
                    bool fold_input) noexcept {
  if (s.size() != length) {
    return false;
  }
  if (!fold_input) {
    return s.size() == 0 || std::memcmp(s.data(), text, s.size()) == 0;
  }
  for (size_t i = 0; i < s.size(); i++) {
    const uint8_t c = static_cast<uint8_t>(s[i]);
    const char folded =
        static_cast<char>(c | ((c >= 'A' && c <= 'Z') ? 0x20u : 0u));
    if (folded != text[i]) {
      return false;
    }
  }
  return true;
}

}  // namespace

bool match_regexp_shape(const compiled_routes& r, uint32_t route,
                        std::string_view pathname, bool fold_input) noexcept {
  const route_record& rt = r.section<route_record>(r.routes_offset)[route];
  const segment_record* segs =
      r.section<segment_record>(r.segments_offset) + rt.segment_first;
  const char* blob = r.section<char>(r.blob_offset);
  if (rt.segment_count == 0 && rt.wild != 0) {
    return true;  // nothing is known about the route's shape
  }
  if (pathname.empty() || pathname[0] != '/') {
    return false;  // a known shape always starts with '/'
  }
  size_t seg_start = 1;
  for (uint32_t si = 0; si < rt.segment_count; si++) {
    if (seg_start > pathname.size()) {
      return false;  // fewer segments than the shape
    }
    const size_t slash = pathname.find('/', seg_start);
    const size_t seg_end =
        slash == std::string_view::npos ? pathname.size() : slash;
    const std::string_view s(pathname.data() + seg_start, seg_end - seg_start);
    if (segs[si].kind == 0) {  // literal
      if (!literal_equals(s, blob + segs[si].text_offset, segs[si].text_length,
                          fold_input)) {
        return false;
      }
    } else if (s.empty()) {
      return false;  // a ":name" group, mixed or not, never binds ""
    }
    seg_start = seg_end + 1;
  }
  // An exact shape admits no further segments.
  return rt.wild != 0 || seg_start == pathname.size() + 1;
}

bool match_route_sequential(const compiled_routes& r, uint32_t route,
                            std::string_view pathname, bool fold_input,
                            engine_result& result) noexcept {
  using url_pattern_list_limits::max_captures_per_route;
  result.capture_count = 0;
  result.captures_truncated = false;
  const route_record& rt = r.section<route_record>(r.routes_offset)[route];
  const segment_record* segs =
      r.section<segment_record>(r.segments_offset) + rt.segment_first;
  const char* blob = r.section<char>(r.blob_offset);
  const size_t n_pattern = rt.segment_count;
  if (n_pattern == 0) {
    return pathname.empty();  // the empty pattern matches only ""
  }
  if (pathname.empty() || pathname[0] != '/') {
    return false;
  }
  const bool wild = rt.wild != 0;  // wildcard is always the last segment
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
    if (segs[si].kind == 0) {  // literal
      if (!literal_equals(s, blob + segs[si].text_offset, segs[si].text_length,
                          fold_input)) {
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
    // "(.*)" does not match a line terminator (see wildcard_tail_ok).
    if (pathname.find_first_of("\n\r", seg_start) != std::string_view::npos) {
      return false;
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

}  // namespace ada::url_pattern_list_detail
#endif  // ADA_INCLUDE_URL_PATTERN
