#include <algorithm>
#include <cstdlib>
#include <random>
#include <string>
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
