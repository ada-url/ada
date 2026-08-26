#include <algorithm>
#include <cstdlib>
#include <map>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "gtest/gtest.h"

#include "ada.h"

using regex_provider = ada::url_pattern_regex::std_regex_provider;
using list_type = ada::url_pattern_list<regex_provider>;

namespace {

std::string capture_text(std::string_view path,
                         const ada::url_pattern_list_match_result& m,
                         size_t index) {
  return std::string(
      path.substr(m.captures[index].offset, m.captures[index].length));
}

list_type make_list(const std::vector<std::string_view>& patterns) {
  auto result = list_type::create(patterns);
  EXPECT_TRUE(result.has_value());
  if (!result.has_value()) {
    return list_type{};
  }
  return std::move(*result);
}

}  // namespace

TEST(url_pattern_list, basic_static_param_wildcard) {
  auto list = make_list({
      "/",                 // 0
      "/about",            // 1
      "/users/:id",        // 2
      "/users/me",         // 3
      "/files/*",          // 4
      "/api/v1/:a/:b",     // 5
      "/users/:id/posts",  // 6
  });
  ASSERT_EQ(list.size(), 7u);
  EXPECT_EQ(list.match("/").route_index, 0);
  EXPECT_EQ(list.match("/about").route_index, 1);
  EXPECT_EQ(list.match("/users/42").route_index, 2);
  EXPECT_EQ(list.match("/users/me").route_index, 3);
  EXPECT_EQ(list.match("/files/a/b/c").route_index, 4);
  EXPECT_EQ(list.match("/api/v1/x/y").route_index, 5);
  EXPECT_EQ(list.match("/users/9/posts").route_index, 6);
  EXPECT_EQ(list.match("/nope").route_index, -1);
  EXPECT_EQ(list.match("/users").route_index, -1);
  EXPECT_EQ(list.match("").route_index, -1);
  EXPECT_EQ(list.match("no-slash").route_index, -1);

  auto m = list.match("/users/42");
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(capture_text("/users/42", m, 0), "42");
  ASSERT_EQ(list.group_names(2).size(), 1u);
  EXPECT_EQ(list.group_names(2)[0], "id");

  auto two = list.match("/api/v1/x/y");
  ASSERT_EQ(two.capture_count, 2u);
  EXPECT_EQ(capture_text("/api/v1/x/y", two, 0), "x");
  EXPECT_EQ(capture_text("/api/v1/x/y", two, 1), "y");

  auto wild = list.match("/files/a/b/c");
  ASSERT_EQ(wild.capture_count, 1u);
  EXPECT_EQ(capture_text("/files/a/b/c", wild, 0), "a/b/c");
  // URLPattern numbers unnamed "*" groups.
  ASSERT_EQ(list.group_names(4).size(), 1u);
  EXPECT_EQ(list.group_names(4)[0], "0");
}

TEST(url_pattern_list, wildcard_boundary_semantics) {
  auto list = make_list({"/files/*"});
  // "/files/*" compiles to ^/files/(.*)$: the '/' is required, the tail may
  // be empty.
  EXPECT_EQ(list.match("/files").route_index, -1);
  auto m = list.match("/files/");
  EXPECT_EQ(m.route_index, 0);
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(m.captures[0].length, 0u);
}

TEST(url_pattern_list, specificity_priority) {
  // literal < ":param" < "*" at the first differing segment.
  auto list = make_list({
      "/*",       // 0
      "/:x",      // 1
      "/a",       // 2
      "/a/*",     // 3
      "/a/:y",    // 4
      "/a/b",     // 5
      "/:x/b",    // 6
      "/a/:y/c",  // 7
      "/w/*",     // 8
      "/:p/x/y",  // 9
  });
  EXPECT_EQ(list.match("/a").route_index, 2);    // static beats param, wild
  EXPECT_EQ(list.match("/z").route_index, 1);    // param beats wildcard
  EXPECT_EQ(list.match("/a/b").route_index, 5);  // static/static wins
  // "/a/*" ([0,2]) vs "/:x/b" ([1,0]): the static first segment dominates.
  EXPECT_EQ(list.match("/a/q").route_index, 4);  // param beats wildcard
  EXPECT_EQ(list.match("/q/b").route_index, 6);
  // Deeper: "/a/:y/c" ([0,1,0]) beats "/a/*" ([0,2]) at position 1.
  EXPECT_EQ(list.match("/a/q/c").route_index, 7);
  EXPECT_EQ(list.match("/a/q/d").route_index, 3);
  // "/w/*" ([0,2]) beats "/:p/x/y" ([1,0,0]) at position 0: this is the
  // wildcard-outranks-a-param-shape case.
  EXPECT_EQ(list.match("/w/x/y").route_index, 8);
  EXPECT_EQ(list.match("/v/x/y").route_index, 9);
}

TEST(url_pattern_list, insertion_order_breaks_ties) {
  auto list = make_list({
      "/users/:a",  // 0
      "/users/:b",  // 1 identical kind sequence: 0 wins
      "/users/me",  // 2
      "/users/me",  // 3 duplicate static: 2 wins
  });
  EXPECT_EQ(list.match("/users/q").route_index, 0);
  EXPECT_EQ(list.match("/users/me").route_index, 2);
}

TEST(url_pattern_list, root_trailing_slash_empty_segments) {
  auto list = make_list({
      "/",        // 0
      "/users/",  // 1 (trailing empty segment)
      "/users",   // 2
      "/a//b",    // 3 (interior empty segment)
      "/:x",      // 4
  });
  EXPECT_EQ(list.match("/").route_index, 0);  // params cannot bind ""
  EXPECT_EQ(list.match("/users/").route_index, 1);
  EXPECT_EQ(list.match("/users").route_index, 2);
  EXPECT_EQ(list.match("/a//b").route_index, 3);
  EXPECT_EQ(list.match("/a/b").route_index, -1);
  EXPECT_EQ(list.match("/q").route_index, 4);
  EXPECT_EQ(list.match("//").route_index, -1);
}

TEST(url_pattern_list, empty_list_and_empty_pattern) {
  auto empty = make_list({});
  EXPECT_EQ(empty.size(), 0u);
  EXPECT_EQ(empty.match("/anything").route_index, -1);

  // The empty pattern matches exactly the empty pathname.
  auto list = make_list({"", "/x"});
  EXPECT_EQ(list.match("").route_index, 0);
  EXPECT_EQ(list.match("/x").route_index, 1);
  EXPECT_EQ(list.match("/").route_index, -1);
}

TEST(url_pattern_list, agrees_with_url_pattern_on_boundary_cases) {
  // Pin the static/":param"/"*" subset semantics to ada::url_pattern itself:
  // for every (pattern, input) pair, a single-route list must match exactly
  // when the URLPattern pathname component matches.
  const std::vector<std::string_view> patterns = {
      "/files/*", "/users/:id", "/users/", "/a//b", "/", "/*", "/:x/:y",
  };
  const std::vector<std::string_view> inputs = {
      "/files",   "/files/",  "/files/x/y", "/users",      "/users/",
      "/users/x", "/users//", "/a//b",      "/a/b",        "/",
      "//",       "/x/y",     "/x/",        "/files/x/y/",
  };
  for (const std::string_view pattern : patterns) {
    auto list = make_list({pattern});
    auto url_pattern = ada::parse_url_pattern<regex_provider>(
        ada::url_pattern_init{.pathname = std::string(pattern)});
    ASSERT_TRUE(url_pattern.has_value()) << pattern;
    for (const std::string_view input : inputs) {
      auto expected = url_pattern->test(
          ada::url_pattern_init{.pathname = std::string(input)});
      ASSERT_TRUE(expected.has_value()) << pattern << " " << input;
      EXPECT_EQ(list.match(input).has_match(), *expected)
          << "pattern=" << pattern << " input=" << input;
    }
  }
}

TEST(url_pattern_list, invalid_pattern_is_type_error) {
  auto result = list_type::create({"/users/(unclosed"});
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), ada::errors::type_error);
}

TEST(url_pattern_list, pattern_canonicalization_percent_encoding) {
  // The pattern side goes through ada's URLPattern canonicalization: literal
  // text is percent-encoded exactly as a URLPattern pathname component
  // would be, so patterns match canonical pathnames.
  auto list = make_list({"/caf\xC3\xA9", "/a b/:id"});
  EXPECT_EQ(list.match("/caf%C3%A9").route_index, 0);
  // The input side is matched as given (canonical form expected).
  EXPECT_EQ(list.match("/caf\xC3\xA9").route_index, -1);
  auto m = list.match("/a%20b/7");
  EXPECT_EQ(m.route_index, 1);
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(capture_text("/a%20b/7", m, 0), "7");
  // The canonicalized pattern is observable through ada::url_pattern too.
  auto pattern = ada::parse_url_pattern<regex_provider>(
      ada::url_pattern_init{.pathname = "/caf\xC3\xA9"});
  ASSERT_TRUE(pattern.has_value());
  EXPECT_EQ(pattern->get_pathname(), "/caf%C3%A9");
}

TEST(url_pattern_list, out_of_fast_path_inputs) {
  auto list = make_list({
      "/files/*",  // 0
      "/deep/:x",  // 1
      "/",         // 2
  });
  // More than 24 segments: must still match the wildcard route, with the
  // full tail captured.
  std::string deep = "/files";
  for (int i = 0; i < 40; i++) {
    deep += "/segment";
  }
  auto m = list.match(deep);
  EXPECT_EQ(m.route_index, 0);
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(capture_text(deep, m, 0), deep.substr(7));

  // Longer than 4096 bytes: same answer, same captures.
  std::string longu = "/files/" + std::string(8000, 'x');
  auto ml = list.match(longu);
  EXPECT_EQ(ml.route_index, 0);
  ASSERT_EQ(ml.capture_count, 1u);
  EXPECT_EQ(ml.captures[0].length, 8000u);

  // A 30-segment miss stays a miss.
  std::string miss = "/deep";
  for (int i = 0; i < 30; i++) {
    miss += "/s";
  }
  EXPECT_EQ(list.match(miss).route_index, -1);
}

TEST(url_pattern_list, many_params_route_is_correct_and_truncates) {
  auto list = make_list({
      "/:a/:b/:c/:d/:e/:f/:g/:h/:i/:j",   // 0: ten params (> 8)
      "/one/:b/:c/:d/:e/:f/:g/:h/:i/:j",  // 1: nine captures, outranks 0
  });
  auto m = list.match("/1/2/3/4/5/6/7/8/9/10");
  EXPECT_EQ(m.route_index, 0);
  EXPECT_EQ(m.capture_count, 8u);
  EXPECT_TRUE(m.captures_truncated);
  EXPECT_EQ(capture_text("/1/2/3/4/5/6/7/8/9/10", m, 0), "1");
  EXPECT_EQ(capture_text("/1/2/3/4/5/6/7/8/9/10", m, 7), "8");
  auto n = list.match("/one/2/3/4/5/6/7/8/9/10");
  EXPECT_EQ(n.route_index, 1);
  EXPECT_EQ(n.capture_count, 8u);
  EXPECT_TRUE(n.captures_truncated);
  EXPECT_EQ(capture_text("/one/2/3/4/5/6/7/8/9/10", n, 0), "2");
  // An input with fewer segments than the pattern: the sequential matcher
  // must reject after binding what is there.
  EXPECT_EQ(list.match("/1/2/3").route_index, -1);
}

TEST(url_pattern_list, large_fanout_falls_back_to_linear_dispatch) {
  // More children under one node than the 8-bit slot tables can index: the
  // node demotes to a linear scan and stays correct.
  std::vector<std::string> storage;
  storage.reserve(300);
  for (int i = 0; i < 300; i++) {
    storage.push_back("/fan/route" + std::to_string(i));
  }
  std::vector<std::string_view> patterns(storage.begin(), storage.end());
  auto list = make_list(patterns);
  EXPECT_EQ(list.match("/fan/route0").route_index, 0);
  EXPECT_EQ(list.match("/fan/route123").route_index, 123);
  EXPECT_EQ(list.match("/fan/route299").route_index, 299);
  EXPECT_EQ(list.match("/fan/route300").route_index, -1);
}

TEST(url_pattern_list, deep_pattern_falls_back_sequential) {
  auto list = make_list({
      "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r",  // 0: 18 segments (> 16)
      "/a/:x/c",                               // 1
  });
  EXPECT_EQ(list.match("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r").route_index, 0);
  EXPECT_EQ(list.match("/a/z/c").route_index, 1);
  // The deep route outranks "/a/:x/c" (all-literal kind sequence), so the
  // sequential matcher tests it on this input and must reject it for having
  // more pattern segments than the input has.
  EXPECT_EQ(list.match("/a/b/c").route_index, 1);
  EXPECT_EQ(list.match("/a/b/c/d").route_index, -1);
}

TEST(url_pattern_list, regexp_routes_compose_with_priority) {
  auto list = make_list({
      "/users/(\\d+)",  // 0: regexp, kind ~ [literal, param]
      "/users/:name",   // 1: same kind sequence; 0 wins on insertion order
      "/users/admin",   // 2: static outranks both
      "/*",             // 3
  });
  EXPECT_EQ(list.match("/users/123").route_index, 0);
  EXPECT_EQ(list.match("/users/bob").route_index, 1);
  EXPECT_EQ(list.match("/users/admin").route_index, 2);
  EXPECT_EQ(list.match("/other").route_index, 3);
  // Group values for regexp routes are not surfaced as slices; the route
  // can be re-executed as a url_pattern for its groups.
  auto m = list.match("/users/123");
  EXPECT_EQ(m.capture_count, 0u);
  ASSERT_EQ(list.group_names(0).size(), 1u);
}

TEST(url_pattern_list, regexp_routes_compose_in_both_directions) {
  {
    // The regexp route is inserted first and wins its priority class.
    auto list = make_list({"/users/(\\d+)", "/users/:name"});
    EXPECT_EQ(list.match("/users/123").route_index, 0);
    EXPECT_EQ(list.match("/users/x").route_index, 1);
  }
  {
    // The safe route is inserted first and wins the tie instead.
    auto list = make_list({"/users/:name", "/users/(\\d+)"});
    EXPECT_EQ(list.match("/users/123").route_index, 0);
    EXPECT_EQ(list.match("/users/x").route_index, 0);
  }
  {
    // A static regexp-free answer still outranks an earlier regexp route,
    // and a regexp-only match is found when nothing else matches.
    auto list = make_list({"/x-(\\d+)", "/x-7"});
    EXPECT_EQ(list.match("/x-7").route_index, 1);
    EXPECT_EQ(list.match("/x-42").route_index, 0);
  }
}

// ---------------------------------------------------------------------------
// Randomized differential test: url_pattern_list::match against a naive,
// engine-independent reference matcher over generated route sets and
// generated + mutated pathnames. Extra seeds can be supplied locally via
// the ADA_URL_PATTERN_LIST_SEEDS environment variable (comma-separated).

namespace {

struct reference_segment {
  int kind;  // 0 literal, 1 param, 2 wildcard
  std::string text;
};

struct reference_route {
  std::vector<reference_segment> segments;
  bool wildcard = false;
};

// Parses the safe pattern subset the generator emits ("/lit/:param/*").
reference_route reference_parse(std::string_view pattern) {
  reference_route route;
  size_t pos = 1;  // skip the leading '/'
  while (pos <= pattern.size()) {
    size_t next = pattern.find('/', pos);
    if (next == std::string_view::npos) {
      next = pattern.size();
    }
    std::string_view token = pattern.substr(pos, next - pos);
    if (token == "*") {
      route.segments.push_back({2, "*"});
      route.wildcard = true;
    } else if (!token.empty() && token[0] == ':') {
      route.segments.push_back({1, std::string(token.substr(1))});
    } else {
      route.segments.push_back({0, std::string(token)});
    }
    pos = next + 1;
  }
  return route;
}

bool reference_match_one(const reference_route& route, std::string_view path,
                         std::vector<std::string>& captures) {
  captures.clear();
  if (path.empty() || path[0] != '/') {
    return false;
  }
  std::vector<std::string_view> segments;
  size_t pos = 1;
  while (pos <= path.size()) {
    size_t next = path.find('/', pos);
    if (next == std::string_view::npos) {
      next = path.size();
    }
    segments.push_back(path.substr(pos, next - pos));
    pos = next + 1;
  }
  const size_t n_pattern = route.segments.size();
  const size_t n_fixed = route.wildcard ? n_pattern - 1 : n_pattern;
  if (route.wildcard ? segments.size() < n_pattern
                     : segments.size() != n_pattern) {
    return false;
  }
  for (size_t i = 0; i < n_fixed; i++) {
    const reference_segment& ps = route.segments[i];
    if (ps.kind == 0) {
      if (segments[i] != ps.text) {
        return false;
      }
    } else {
      if (segments[i].empty()) {
        return false;
      }
      captures.emplace_back(segments[i]);
    }
  }
  if (route.wildcard) {
    const char* tail_begin = segments[n_fixed].data();
    captures.emplace_back(
        tail_begin,
        static_cast<size_t>(path.data() + path.size() - tail_begin));
  }
  return true;
}

// The documented priority rule, computed naively: per-segment kind sequence
// compared lexicographically, insertion index as the tiebreak.
int reference_best(const std::vector<reference_route>& routes,
                   std::string_view path, std::vector<std::string>& captures) {
  int best = -1;
  std::vector<int> best_kinds;
  std::vector<std::string> scratch;
  for (size_t i = 0; i < routes.size(); i++) {
    if (!reference_match_one(routes[i], path, scratch)) {
      continue;
    }
    std::vector<int> kinds;
    kinds.reserve(routes[i].segments.size());
    for (const auto& s : routes[i].segments) {
      kinds.push_back(s.kind);
    }
    if (best < 0 ||
        std::lexicographical_compare(kinds.begin(), kinds.end(),
                                     best_kinds.begin(), best_kinds.end())) {
      best = static_cast<int>(i);
      best_kinds = std::move(kinds);
      captures = scratch;
    }
  }
  return best;
}

void run_differential(uint64_t seed) {
  std::mt19937_64 rng(seed);
  const auto pick = [&](uint64_t n) { return rng() % n; };
  static const char* vocabulary[] = {
      "api",
      "v1",
      "v2",
      "users",
      "posts",
      "comments",
      "orders",
      "items",
      "admin",
      "auth",
      "login",
      "settings",
      "files",
      "static",
      "img",
      "js",
      "a",
      "b",
      "long-segment-name-for-keys",
  };
  constexpr size_t vocabulary_size = sizeof(vocabulary) / sizeof(vocabulary[0]);

  // ~200 generated routes over a small vocabulary, so prefixes collide and
  // the trie, exact-table and shape-table paths all populate.
  std::vector<std::string> storage;
  std::vector<reference_route> reference_routes;
  const size_t n_routes = 200;
  for (size_t i = 0; i < n_routes; i++) {
    std::string pattern;
    const size_t depth = 1 + pick(6);
    int params = 0;
    for (size_t d = 0; d < depth; d++) {
      const bool last = d + 1 == depth;
      const uint64_t kind = pick(10);
      if (last && kind < 2) {
        pattern += "/*";
      } else if (kind < 5 && params < 4) {
        pattern += "/:p" + std::to_string(params++);
      } else {
        pattern += '/';
        pattern += vocabulary[pick(vocabulary_size)];
      }
    }
    storage.push_back(std::move(pattern));
    reference_routes.push_back(reference_parse(storage.back()));
  }
  std::vector<std::string_view> patterns(storage.begin(), storage.end());
  auto result = list_type::create(patterns);
  ASSERT_TRUE(result.has_value());
  const auto& list = *result;

  // The same route set as individual ada::url_pattern objects: on a sample of
  // inputs, every route's url_pattern::test must agree with the reference
  // matcher, tying the reference (and through it the winner check below) to
  // URLPattern semantics rather than to this test's own parser.
  std::vector<ada::url_pattern<regex_provider>> url_patterns;
  url_patterns.reserve(n_routes);
  for (const std::string& pattern : storage) {
    auto parsed = ada::parse_url_pattern<regex_provider>(
        ada::url_pattern_init{.pathname = pattern});
    ASSERT_TRUE(parsed.has_value()) << pattern;
    url_patterns.push_back(std::move(*parsed));
  }

  const auto random_token = [&]() {
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789-_";
    const size_t len = 1 + pick(10);
    std::string token;
    for (size_t j = 0; j < len; j++) {
      token += alphabet[pick(sizeof(alphabet) - 1)];
    }
    return token;
  };

  std::vector<std::string> reference_captures;
  const size_t n_urls = 20000;
  for (size_t u = 0; u < n_urls; u++) {
    // Instantiate a random route, then mutate.
    const reference_route& base = reference_routes[pick(n_routes)];
    std::string path;
    for (const auto& seg : base.segments) {
      if (seg.kind == 0) {
        path += '/';
        path += seg.text;
      } else if (seg.kind == 1) {
        path += '/';
        path += random_token();
      } else {
        const uint64_t tail = pick(4);
        for (uint64_t t = 0; t < tail; t++) {
          path += '/';
          path += random_token();
        }
        if (tail == 0) {
          path += '/';
          if (pick(2)) {
            path += random_token();
          }
        }
      }
    }
    if (path.empty()) {
      path = "/";
    }
    switch (pick(8)) {
      case 0:  // flip one byte
        if (!path.empty()) {
          path[pick(path.size())] =
              static_cast<char>('a' + static_cast<char>(pick(26)));
        }
        break;
      case 1:  // add a trailing slash
        path += '/';
        break;
      case 2:  // drop the last segment
        if (path.find_last_of('/') > 0) {
          path.resize(path.find_last_of('/'));
        }
        break;
      case 3:  // append a segment
        path += '/';
        path += random_token();
        break;
      case 4:  // empty out one segment
        path.insert(pick(path.size()), "/");
        break;
      case 5:  // occasionally exceed the fast-path segment limit
        if (pick(10) == 0) {
          for (int t = 0; t < 30; t++) {
            path += "/s";
          }
        }
        break;
      default:
        break;  // keep the instantiated path
    }

    const int expected =
        reference_best(reference_routes, path, reference_captures);
    const auto matched = list.match(path);
    ASSERT_EQ(matched.route_index, expected)
        << "seed=" << seed << " path=" << path;
    if (u % 50 == 0) {
      // Sampled cross-check: per-route url_pattern::test agreement. Inputs
      // generated here are already in canonical form, so testing them as a
      // pathname init is an identity transformation.
      std::vector<std::string> scratch;
      for (size_t i = 0; i < n_routes; i++) {
        auto tested =
            url_patterns[i].test(ada::url_pattern_init{.pathname = path});
        ASSERT_TRUE(tested.has_value())
            << "seed=" << seed << " path=" << path << " route=" << i;
        ASSERT_EQ(*tested,
                  reference_match_one(reference_routes[i], path, scratch))
            << "seed=" << seed << " path=" << path << " route=" << i
            << " pattern=" << storage[i];
      }
    }
    if (expected >= 0) {
      const size_t n_reported = std::min<size_t>(
          reference_captures.size(),
          ada::url_pattern_list_helpers::max_captures_per_route);
      ASSERT_EQ(matched.capture_count, n_reported)
          << "seed=" << seed << " path=" << path;
      for (size_t c = 0; c < n_reported; c++) {
        ASSERT_EQ(capture_text(path, matched, c), reference_captures[c])
            << "seed=" << seed << " path=" << path << " capture=" << c;
      }
    }
  }
}

}  // namespace

TEST(url_pattern_list, differential_against_reference) {
  run_differential(0xADA0001ull);
  if (const char* extra = std::getenv("ADA_URL_PATTERN_LIST_SEEDS")) {
    std::string_view seeds(extra);
    while (!seeds.empty()) {
      const size_t comma = seeds.find(',');
      const std::string one(seeds.substr(0, comma));
      run_differential(std::strtoull(one.c_str(), nullptr, 0));
      if (comma == std::string_view::npos) {
        break;
      }
      seeds.remove_prefix(comma + 1);
    }
  }
}

// ---------------------------------------------------------------------------
// Data-driven semantics table: (pattern, input, expected match, expected
// captures) triplets in the style of ada's WPT tables, covering every syntax
// feature the static/":param"/"*" subset supports, its boundaries into
// regexp mode, and pattern-side canonicalization interactions. Rows with
// crosscheck == true are additionally verified against ada::url_pattern::test
// so the table can never drift from URLPattern semantics (rows whose input is
// not in canonical form are excluded: url_pattern canonicalizes the tested
// pathname, url_pattern_list matches it as given).

namespace {

struct semantics_case {
  const char* pattern;
  const char* input;
  bool matches;
  // Expected capture count, or -1 to skip capture checks (regexp-mode routes
  // report no capture slices).
  int capture_count;
  // The expected capture values, joined with '|' (exactly capture_count
  // entries; empty entries denote empty captures).
  const char* captures;
  bool crosscheck = true;
};

constexpr semantics_case semantics_table[] = {
    // --- root and plain statics ---
    {"/", "/", true, 0, ""},
    {"/", "", false, -1, "", false},
    {"/", "//", false, 0, ""},
    {"/about", "/about", true, 0, ""},
    {"/about", "/about/", false, 0, ""},
    {"/about", "/abut", false, 0, ""},
    {"/about", "/abouT", false, 0, ""},
    {"/about", "/about%20", false, 0, ""},
    {"/a/b/c", "/a/b/c", true, 0, ""},
    {"/a/b/c", "/a/b", false, 0, ""},
    {"/a/b/c", "/a/b/c/d", false, 0, ""},
    {"/A/B", "/A/B", true, 0, ""},
    {"/A/B", "/a/b", false, 0, ""},
    // --- trailing and interior empty segments ---
    {"/users/", "/users/", true, 0, ""},
    {"/users/", "/users", false, 0, ""},
    {"/users/", "/users//", false, 0, ""},
    {"/a//b", "/a//b", true, 0, ""},
    {"/a//b", "/a/b", false, 0, ""},
    {"//", "//", true, 0, ""},
    {"//", "/", false, 0, ""},
    // --- static keys around the 8/16-byte verify windows ---
    {"/abcdefgh", "/abcdefgh", true, 0, ""},  // exactly 8
    {"/abcdefgh", "/abcdefgX", false, 0, ""},
    {"/abcdefghijklmnop", "/abcdefghijklmnop", true, 0, ""},  // exactly 16
    {"/abcdefghijklmnop", "/abcdefghijklmnoX", false, 0, ""},
    {"/abcdefghijklmnopq", "/abcdefghijklmnopq", true, 0, ""},  // 17: blob
    {"/abcdefghijklmnopq", "/abcdefghXjklmnopq", false, 0, ""},
    {"/segment-longer-than-sixteen-bytes/x",
     "/segment-longer-than-sixteen-bytes/x", true, 0, ""},
    {"/segment-longer-than-sixteen-bytes/x",
     "/segment-longer-than-sixteen-bytef/x", false, 0, ""},
    // --- single params ---
    {"/users/:id", "/users/42", true, 1, "42"},
    {"/users/:id", "/users/", false, 0, ""},
    {"/users/:id", "/users", false, 0, ""},
    {"/users/:id", "/users/42/x", false, 0, ""},
    {"/users/:id", "/Users/42", false, 0, ""},
    {"/users/:id", "/users/a.b-c_d", true, 1, "a.b-c_d"},
    {"/users/:id", "/users/%20", true, 1, "%20"},
    {"/users/:id", "/users/x%2Fy", true, 1, "x%2Fy"},
    {"/:solo", "/anything", true, 1, "anything"},
    {"/:solo", "/", false, 0, ""},
    {"/:solo", "/a/b", false, 0, ""},
    // --- multiple params and mixed shapes ---
    {"/:a/:b/:c", "/1/2/3", true, 3, "1|2|3"},
    {"/:a/:b/:c", "/1/2", false, 0, ""},
    {"/:a/:b/:c", "/1//3", false, 0, ""},
    {"/a/:b/c/:d/e", "/a/1/c/2/e", true, 2, "1|2"},
    {"/a/:b/c/:d/e", "/a/1/x/2/e", false, 0, ""},
    {"/a/:b/c/:d/e", "/a/1/c/2/x", false, 0, ""},
    {"/api/v1/:res/:id", "/api/v1/users/7", true, 2, "users|7"},
    {"/api/v1/:res/:id", "/api/v2/users/7", false, 0, ""},
    // --- wildcards ---
    {"/files/*", "/files/a", true, 1, "a"},
    {"/files/*", "/files/a/b/c", true, 1, "a/b/c"},
    {"/files/*", "/files/", true, 1, ""},
    {"/files/*", "/files", false, 0, ""},
    {"/files/*", "/filesx", false, 0, ""},
    {"/files/*", "/files/a/", true, 1, "a/"},
    {"/*", "/", true, 1, ""},
    {"/*", "/a", true, 1, "a"},
    {"/*", "/a/b/c", true, 1, "a/b/c"},
    {"/:x/*", "/a/b/c", true, 2, "a|b/c"},
    {"/:x/*", "/a/", true, 2, "a|"},
    {"/:x/*", "/a", false, 0, ""},
    {"/a/:b/*", "/a/b/c/d", true, 2, "b|c/d"},
    // --- pattern-side canonicalization ---
    {"/a b", "/a%20b", true, 0, ""},
    {"/a b", "/a b", false, 0, "", false},  // input matched as given
    {"/caf\xC3\xA9", "/caf%C3%A9", true, 0, ""},
    {"/caf\xC3\xA9", "/caf\xC3\xA9", false, 0, "", false},
    {"/%41", "/%41", true, 0, ""},
    {"/%41", "/A", false, 0, ""},
    {"/<x>", "/%3Cx%3E", true, 0, ""},
    {"/\"q\"", "/%22q%22", true, 0, ""},
    {"/'quote'", "/'quote'", true, 0, ""},
    {"/~tilde", "/~tilde", true, 0, ""},
    {"/x%3ay", "/x%3ay", true, 0, "", false},
    {"/a b/:id", "/a%20b/7", true, 1, "7"},
    {"/caf\xC3\xA9/*", "/caf%C3%A9/x/y", true, 1, "x/y"},
    // --- the empty pattern ---
    {"", "", true, 0, "", false},
    {"", "/", false, 0, "", false},
    // --- braces resolving into the safe subset ---
    {"/{:id}", "/q", true, 1, "q"},
    {"/{:id}", "/", false, 0, ""},
    // --- subset boundaries: these compile through the regex provider ---
    {"/users/(\\d+)", "/users/123", true, -1, ""},
    {"/users/(\\d+)", "/users/12a", false, -1, ""},
    {"/users/(\\d+)", "/users/", false, -1, ""},
    {"/:id?", "/x", true, -1, ""},
    {"/:id?", "/", false, -1, ""},
    {"/:id?", "", true, -1, "", false},
    {"/:id+", "/a/b", true, -1, ""},
    {"/:id*", "/a/b/c", true, -1, ""},
    {"/a/*/b", "/a/x/b", true, -1, ""},
    {"/a/*/b", "/a/x/y/b", true, -1, ""},
    {"/a/*/b", "/a/b", false, -1, ""},
    {"/*.js", "/app.js", true, -1, ""},
    {"/*.js", "/app.css", false, -1, ""},
    {"/*x", "/ax", true, -1, ""},
    {"/*x", "/a", false, -1, ""},
    {"x", "x", true, -1, "", false},
    {"x", "/x", false, -1, "", false},
    {"/foo-:id", "/foo-7", true, -1, ""},
    {"/foo-:id", "/foo-", false, -1, ""},
    {"/foo-:id", "/foo", false, -1, ""},
    {"/x{:id}", "/xq", true, -1, ""},
    {"/x{:id}", "/x", false, -1, ""},
    {"/{a:id}", "/aq", true, -1, ""},
    {"/{a:id}", "/q", false, -1, ""},
    {"/:a{:b}", "/pq", true, -1, ""},
    {"/:a{:b}", "/p", false, -1, ""},
    {"/{ab}?", "/ab", true, -1, ""},
    {"/{ab}?", "/", true, -1, ""},
    {"/{ab}?", "/abab", false, -1, ""},
    {"/{:id-}", "/x-", true, -1, ""},
    {"/{:id-}", "/x", false, -1, ""},
    {"/:id.json", "/report.json", true, -1, ""},
    {"/:id.json", "/report.csv", false, -1, ""},
    {"/*/*", "/a/b", true, -1, ""},
    {"/*/*", "/a", false, -1, ""},
    {":id", "x", true, -1, "", false},
    {":id", "/x", false, -1, "", false},
    {"{:id}", "x", true, -1, "", false},
    {"{:id}", "/x", false, -1, "", false},
    {"(\\d+)", "123", true, -1, "", false},
    {"(\\d+)", "x", false, -1, "", false},
    // --- specificity inside a single-route list is trivial, but a static
    // pattern that looks like a param must stay literal after escaping ---
    {"/\\:id", "/:id", true, 0, ""},
    {"/\\:id", "/x", false, 0, ""},
    {"/\\*", "/*", true, 0, ""},
    {"/\\*", "/x", false, 0, ""},
};

}  // namespace

TEST(url_pattern_list, data_driven_semantics_table) {
  std::map<std::string, list_type> lists;
  std::map<std::string, ada::url_pattern<regex_provider>> url_patterns;
  for (const semantics_case& c : semantics_table) {
    const std::string pattern(c.pattern);
    auto it = lists.find(pattern);
    if (it == lists.end()) {
      auto created = list_type::create({c.pattern});
      ASSERT_TRUE(created.has_value()) << "pattern=" << c.pattern;
      it = lists.emplace(pattern, std::move(*created)).first;
    }
    const auto m = it->second.match(c.input);
    EXPECT_EQ(m.has_match(), c.matches)
        << "pattern=" << c.pattern << " input=" << c.input;
    if (c.matches && c.capture_count >= 0) {
      ASSERT_EQ(m.capture_count, static_cast<uint32_t>(c.capture_count))
          << "pattern=" << c.pattern << " input=" << c.input;
      std::string_view expected(c.captures);
      for (int k = 0; k < c.capture_count; k++) {
        const size_t bar = expected.find('|');
        const std::string_view value = expected.substr(0, bar);
        EXPECT_EQ(capture_text(c.input, m, static_cast<size_t>(k)), value)
            << "pattern=" << c.pattern << " input=" << c.input
            << " capture=" << k;
        expected = bar == std::string_view::npos ? std::string_view{}
                                                 : expected.substr(bar + 1);
      }
    }
    if (c.crosscheck) {
      auto up = url_patterns.find(pattern);
      if (up == url_patterns.end()) {
        auto parsed = ada::parse_url_pattern<regex_provider>(
            ada::url_pattern_init{.pathname = pattern});
        ASSERT_TRUE(parsed.has_value()) << "pattern=" << c.pattern;
        up = url_patterns.emplace(pattern, std::move(*parsed)).first;
      }
      auto tested = up->second.test(
          ada::url_pattern_init{.pathname = std::string(c.input)});
      ASSERT_TRUE(tested.has_value())
          << "pattern=" << c.pattern << " input=" << c.input;
      EXPECT_EQ(*tested, c.matches)
          << "url_pattern disagrees: pattern=" << c.pattern
          << " input=" << c.input;
    }
  }
}

// ---------------------------------------------------------------------------
// Targeted engine tests: each one drives a specific build-time or match-time
// rung (dispatch ladders, offline-search failures, demotions, gates) that the
// happy path never reaches.

TEST(url_pattern_list, witness_exhaustion_demotes_node_and_static_table) {
  // 17-byte segments that differ only at byte 8: no witness plan over the
  // first/last 8 bytes plus the length can tell them apart, so the offline
  // searches fail and both the node dispatch and the whole-pathname exact
  // table demote (the table is simply not built). Matching must not care.
  auto list = make_list({
      "/aaaaaaaaBaaaaaaaa",  // 0
      "/aaaaaaaaCaaaaaaaa",  // 1
      "/aaaaaaaaDaaaaaaaa",  // 2
  });
  EXPECT_EQ(list.match("/aaaaaaaaBaaaaaaaa").route_index, 0);
  EXPECT_EQ(list.match("/aaaaaaaaCaaaaaaaa").route_index, 1);
  EXPECT_EQ(list.match("/aaaaaaaaDaaaaaaaa").route_index, 2);
  EXPECT_EQ(list.match("/aaaaaaaaEaaaaaaaa").route_index, -1);
  EXPECT_EQ(list.match("/aaaaaaaaBaaaaaaaZ").route_index, -1);
  EXPECT_EQ(list.match("/aaaaaaaaBaaaaaaa").route_index, -1);
}

TEST(url_pattern_list, witness_exhaustion_demotes_shape_group) {
  // The same 17-byte statics as leading segments of ":param" routes: the
  // shape group has no usable witness column at all (k == 0) and demotes to
  // a linear scan; captures and misses stay exact.
  auto list = make_list({
      "/aaaaaaaaBaaaaaaaa/:id",  // 0
      "/aaaaaaaaCaaaaaaaa/:id",  // 1
      "/aaaaaaaaDaaaaaaaa/:id",  // 2
  });
  auto m = list.match("/aaaaaaaaCaaaaaaaa/42");
  EXPECT_EQ(m.route_index, 1);
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(capture_text("/aaaaaaaaCaaaaaaaa/42", m, 0), "42");
  EXPECT_EQ(list.match("/aaaaaaaaEaaaaaaaa/42").route_index, -1);
  EXPECT_EQ(list.match("/aaaaaaaaCaaaaaaaa/").route_index, -1);
  EXPECT_EQ(list.match("/aaaaaaaaCaaaaaaaa").route_index, -1);
}

TEST(url_pattern_list, shape_witness_columns_exist_but_never_separate) {
  // Routes 0 and 1 collide in every addressable byte while routes 2-6 keep
  // five distinct witness columns alive: the four-witness subset search runs
  // through every combination (rotating its combination cursor past the last
  // position) and exhausts without an injective plan, so the group demotes
  // to a linear scan.
  auto list = make_list({
      "/aaaaaaaaBaaaaaaaa/:id",  // 0
      "/aaaaaaaaCaaaaaaaa/:id",  // 1 (indistinguishable from 0 by witnesses)
      "/baaaaaaaXaaaaaaaa/:id",  // 2 (byte 0 column)
      "/acaaaaaaXaaaaaaaa/:id",  // 3 (byte 1 column)
      "/aadaaaaaXaaaaaaaa/:id",  // 4 (byte 2 column)
      "/aaaeaaaaXaaaaaaaa/:id",  // 5 (byte 3 column)
      "/aaaafaaaXaaaaaaaa/:id",  // 6 (byte 4 column)
  });
  EXPECT_EQ(list.match("/aaaaaaaaBaaaaaaaa/1").route_index, 0);
  EXPECT_EQ(list.match("/aaaaaaaaCaaaaaaaa/2").route_index, 1);
  EXPECT_EQ(list.match("/baaaaaaaXaaaaaaaa/3").route_index, 2);
  EXPECT_EQ(list.match("/aaaafaaaXaaaaaaaa/4").route_index, 6);
  EXPECT_EQ(list.match("/zaaaaaaaXaaaaaaaa/3").route_index, -1);
  EXPECT_EQ(list.match("/aaaaaaaaBaaaaaaaa").route_index, -1);
}

TEST(url_pattern_list, shape_single_column_plan) {
  // Single-character statics: the first-byte column alone is injective (and
  // the last-byte column is pruned as its duplicate), so the group compiles
  // with a one-witness plan.
  auto list = make_list({
      "/a/:id",  // 0
      "/b/:id",  // 1
      "/c/:id",  // 2
  });
  auto m = list.match("/b/7");
  EXPECT_EQ(m.route_index, 1);
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(capture_text("/b/7", m, 0), "7");
  EXPECT_EQ(list.match("/d/7").route_index, -1);
  EXPECT_EQ(list.match("/b/").route_index, -1);
}

TEST(url_pattern_list, shape_with_many_static_segments) {
  // Nine static segments and a trailing param: the witness alphabet only
  // addresses the first eight statics, and four witnesses cannot cover all
  // of them, so the coverage-preferring search runs its want-descending
  // loop. Three same-shape routes force a projection table.
  auto list = make_list({
      "/a1/a2/a3/a4/a5/a6/a7/a8/a9/:id",  // 0
      "/b1/b2/b3/b4/b5/b6/b7/b8/b9/:id",  // 1
      "/c1/c2/c3/c4/c5/c6/c7/c8/c9/:id",  // 2
  });
  auto m = list.match("/b1/b2/b3/b4/b5/b6/b7/b8/b9/id42");
  EXPECT_EQ(m.route_index, 1);
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(capture_text("/b1/b2/b3/b4/b5/b6/b7/b8/b9/id42", m, 0), "id42");
  EXPECT_EQ(list.match("/b1/b2/b3/b4/b5/b6/b7/b8/x9/id42").route_index, -1);
  EXPECT_EQ(list.match("/b1/b2/b3/b4/b5/b6/b7/b8/b9").route_index, -1);
}

TEST(url_pattern_list, shape_group_beyond_dispatch_table_capacity) {
  // 260 routes of one shape: more entries than 8-bit slot ordinals can
  // index, so the group skips the witness search entirely and runs linear.
  std::vector<std::string> storage;
  storage.reserve(260);
  for (int i = 0; i < 260; i++) {
    storage.push_back("/m" + std::to_string(i) + "/:id");
  }
  std::vector<std::string_view> patterns(storage.begin(), storage.end());
  auto list = make_list(patterns);
  auto m = list.match("/m0/x");
  EXPECT_EQ(m.route_index, 0);
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(capture_text("/m0/x", m, 0), "x");
  EXPECT_EQ(list.match("/m259/y").route_index, 259);
  EXPECT_EQ(list.match("/m260/z").route_index, -1);
  EXPECT_EQ(list.match("/m131/").route_index, -1);
}

TEST(url_pattern_list, slot_tables_beyond_64_keys) {
  // More than 64 keys in one dispatch table (both the root node's fanout and
  // the whole-pathname exact table): the multiplier search starts with the
  // loosened load factor.
  std::vector<std::string> storage;
  storage.reserve(80);
  for (int i = 0; i < 80; i++) {
    storage.push_back("/k" + std::to_string(i / 10) + std::to_string(i % 10));
  }
  std::vector<std::string_view> patterns(storage.begin(), storage.end());
  auto list = make_list(patterns);
  EXPECT_EQ(list.match("/k00").route_index, 0);
  EXPECT_EQ(list.match("/k42").route_index, 42);
  EXPECT_EQ(list.match("/k79").route_index, 79);
  EXPECT_EQ(list.match("/k80").route_index, -1);
  EXPECT_EQ(list.match("/k7").route_index, -1);
}

TEST(url_pattern_list, huge_static_key_disables_exact_table) {
  // A static route whose whole-pathname key exceeds the 16-bit entry length:
  // the exact table is not built at all and every route answers through the
  // trie or the sequential fallback (the 70001-byte input is beyond the
  // fast-path length limit).
  const std::string huge = "/" + std::string(70000, 'a');
  auto list = make_list({huge, "/ok"});
  EXPECT_EQ(list.match(huge).route_index, 0);
  EXPECT_EQ(list.match("/ok").route_index, 1);
  EXPECT_EQ(list.match(huge + "b").route_index, -1);
  EXPECT_EQ(list.match("/" + std::string(69999, 'a')).route_index, -1);
}

TEST(url_pattern_list, segment_count_gate_boundaries) {
  auto list = make_list({
      "/w/*",   // 0
      "/x/:y",  // 1 (so shape tables exist)
  });
  const auto with_segments = [](int n) {
    std::string path = "/w";
    for (int i = 1; i < n; i++) {
      path += "/s";
    }
    return path;
  };
  // 23 and 24 segments stay on the fast path; 25 is the exact-overflow case
  // of the segment scan (detected only after the loop); 26+ overflow inside
  // the scan. All must keep matching identically through the fallback.
  for (int n : {23, 24, 25, 26, 30}) {
    auto m = list.match(with_segments(n));
    EXPECT_EQ(m.route_index, 0) << n;
    ASSERT_EQ(m.capture_count, 1u) << n;
    EXPECT_EQ(capture_text(with_segments(n), m, 0), with_segments(n).substr(3))
        << n;
  }
  // 17 to 24 segments are within the fast path but beyond the deepest
  // possible shape group; the shape directory must pass without probing.
  std::string deep17 = "/x";
  for (int i = 1; i < 17; i++) {
    deep17 += "/s";
  }
  EXPECT_EQ(list.match(deep17).route_index, -1);
  EXPECT_EQ(list.match("/x/hit").route_index, 1);
}

TEST(url_pattern_list, probe_order_promotion_with_shared_static_position) {
  // Two shape groups of the three-segment class share static position 1 and
  // conflict there in every entry pair ("mm" vs "qq"): the larger group is
  // provably order-independent from the smaller lexicographically-earlier
  // one and is promoted ahead of it in probe order. Winners must be exactly
  // the specificity-order winners regardless.
  auto list = make_list({
      "/:x/mm/a1",  // 0
      "/:x/mm/a2",  // 1
      "/:x/mm/a3",  // 2
      "/pp/qq/:z",  // 3 (outranks 0-2 whenever both could match)
  });
  EXPECT_EQ(list.match("/pp/mm/a1").route_index, 0);
  EXPECT_EQ(list.match("/zz/mm/a3").route_index, 2);
  EXPECT_EQ(list.match("/pp/qq/tail").route_index, 3);
  EXPECT_EQ(list.match("/pp/qq/a1").route_index, 3);
  EXPECT_EQ(list.match("/pp/mm/a4").route_index, -1);
  EXPECT_EQ(list.match("/pp/rr/a1").route_index, -1);
}

TEST(url_pattern_list, dependent_shape_groups_keep_lexicographic_order) {
  // Three shape groups in the three-segment class. The last (and largest)
  // group shares static position 1 with the first, with the SAME text "q":
  // a pathname can match entries of both, so the pair is not
  // order-independent and the large group must not be promoted past it
  // (the middle group makes the promotion scan re-test its head loop).
  auto list = make_list({
      "/p/q/:z",   // 0 (kinds [0,0,1])
      "/p/:y/r",   // 1 (kinds [0,1,0])
      "/:x/q/s1",  // 2 (kinds [1,0,0])
      "/:x/q/s2",  // 3
      "/:x/q/s3",  // 4
  });
  auto m = list.match("/p/q/s1");
  EXPECT_EQ(m.route_index, 0);  // overlaps route 2; route 0 outranks it
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(capture_text("/p/q/s1", m, 0), "s1");
  EXPECT_EQ(list.match("/w/q/s2").route_index, 3);
  EXPECT_EQ(list.match("/p/w/r").route_index, 1);
  EXPECT_EQ(list.match("/p/q/r").route_index, 0);  // beats "/p/:y/r" too
  EXPECT_EQ(list.match("/w/q/s4").route_index, -1);
}

TEST(url_pattern_list, kind_sequences_beyond_the_packed_prefix) {
  // Kind sequences pack at most 32 segments and kind lengths saturate at
  // 255: patterns beyond both caps must still build and match exactly.
  std::string longpat;
  for (int i = 0; i < 260; i++) {
    longpat += "/x";
  }
  std::string repat;
  for (int i = 0; i < 259; i++) {
    repat += "/a";
  }
  repat += "/(\\d+)";
  auto list = make_list({longpat, repat});
  EXPECT_EQ(list.match(longpat).route_index, 0);
  EXPECT_EQ(list.match(longpat + "/x").route_index, -1);
  std::string reinput;
  for (int i = 0; i < 259; i++) {
    reinput += "/a";
  }
  reinput += "/77";
  EXPECT_EQ(list.match(reinput).route_index, 1);
  EXPECT_EQ(list.match(reinput + "x").route_index, -1);
}

TEST(url_pattern_list, sequential_wildcard_still_needs_its_segment) {
  // Nine params plus "*" is ten captures: beyond the fast-path capture
  // limit, so the route is matched sequentially. The wildcard still demands
  // a tenth (possibly empty) segment.
  auto list = make_list({"/:a/:b/:c/:d/:e/:f/:g/:h/:i/*"});
  EXPECT_EQ(list.match("/1/2/3/4/5/6/7/8/9").route_index, -1);
  auto m = list.match("/1/2/3/4/5/6/7/8/9/");
  EXPECT_EQ(m.route_index, 0);
  EXPECT_EQ(m.capture_count, 8u);
  EXPECT_TRUE(m.captures_truncated);
  auto n = list.match("/1/2/3/4/5/6/7/8/9/tail/more");
  EXPECT_EQ(n.route_index, 0);
  EXPECT_EQ(n.capture_count, 8u);
  EXPECT_TRUE(n.captures_truncated);
  EXPECT_EQ(capture_text("/1/2/3/4/5/6/7/8/9/tail/more", n, 7), "8");
}

TEST(url_pattern_list, create_errors) {
  // Not a valid URLPattern pathname pattern at all.
  EXPECT_FALSE(list_type::create({"/users/(unclosed"}).has_value());
  // A '?' modifier cannot follow plain text.
  EXPECT_FALSE(list_type::create({"/a?b"}).has_value());
  // Duplicate group name within one pattern is a URLPattern type error.
  auto dup = list_type::create({"/:id/:id"});
  ASSERT_FALSE(dup.has_value());
  EXPECT_EQ(dup.error(), ada::errors::type_error);
  // Tokenizes fine but the generated regex is rejected by the provider
  // (invalid interval), which create must surface as the same error.
  auto bad_regex = list_type::create({"/(a{2,1})"});
  ASSERT_FALSE(bad_regex.has_value());
  EXPECT_EQ(bad_regex.error(), ada::errors::type_error);
  // One bad pattern anywhere fails the whole list.
  EXPECT_FALSE(
      list_type::create({"/fine", "/also/:ok", "/(a{2,1})"}).has_value());
}

TEST(url_pattern_list, group_names_and_capture_alignment) {
  auto list = make_list({
      "/u/:id",              // 0
      "/v/:id",              // 1: same group name in another route is fine
      "/w/:id/:id2",         // 2
      "/f/*",                // 3: unnamed wildcard gets a numeric name
      "/:a/mid/:b/*",        // 4: params first, then the wildcard
      "/users/(\\d+)",       // 5: regexp route, numbered group
      "/@:handle/x-(\\w+)",  // 6: named and numbered groups mixed
  });
  EXPECT_EQ(list.group_names(0), std::vector<std::string>{"id"});
  EXPECT_EQ(list.group_names(1), std::vector<std::string>{"id"});
  EXPECT_EQ(list.group_names(2), (std::vector<std::string>{"id", "id2"}));
  EXPECT_EQ(list.group_names(3), std::vector<std::string>{"0"});
  EXPECT_EQ(list.group_names(4), (std::vector<std::string>{"a", "b", "0"}));
  EXPECT_EQ(list.group_names(5), std::vector<std::string>{"0"});
  EXPECT_EQ(list.group_names(6), (std::vector<std::string>{"handle", "0"}));

  // Captures align with group_names order: params left to right, then "*".
  const std::string path = "/left/mid/right/t1/t2";
  auto m = list.match(path);
  EXPECT_EQ(m.route_index, 4);
  ASSERT_EQ(m.capture_count, 3u);
  EXPECT_EQ(capture_text(path, m, 0), "left");
  EXPECT_EQ(capture_text(path, m, 1), "right");
  EXPECT_EQ(capture_text(path, m, 2), "t1/t2");

  // Regexp routes surface their names but no capture slices; the same
  // pattern as a url_pattern yields the group values.
  auto r = list.match("/users/123");
  EXPECT_EQ(r.route_index, 5);
  EXPECT_EQ(r.capture_count, 0u);
}
