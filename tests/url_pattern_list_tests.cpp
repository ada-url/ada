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

tl::expected<list_type, ada::errors> parse_list(
    const std::vector<std::string_view>& patterns,
    const ada::url_pattern_options* options = nullptr) {
  return ada::parse_url_pattern_list<regex_provider>(patterns, nullptr,
                                                     options);
}

list_type make_list(const std::vector<std::string_view>& patterns,
                    const ada::url_pattern_options* options = nullptr) {
  auto result = parse_list(patterns, options);
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
  auto result = parse_list({"/users/(unclosed"});
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
  // Group values for regexp routes come back from the provider's
  // regex_search, aligned with group_names.
  auto m = list.match("/users/123");
  EXPECT_TRUE(m.regexp_route);
  EXPECT_EQ(m.capture_count, 0u);
  ASSERT_EQ(list.group_names(0).size(), 1u);
  ASSERT_EQ(m.regexp_groups.size(), 1u);
  EXPECT_EQ(m.regexp_groups[0], std::optional<std::string>("123"));
  // Subset routes report slices and no regexp groups.
  auto n = list.match("/users/bob");
  EXPECT_FALSE(n.regexp_route);
  EXPECT_TRUE(n.regexp_groups.empty());
  ASSERT_EQ(n.capture_count, 1u);
  EXPECT_EQ(capture_text("/users/bob", n, 0), "bob");
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
  // every dispatch rung of the trie populates.
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
  auto result = parse_list(patterns);
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
          ada::url_pattern_list_limits::max_captures_per_route);
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
  // Expected capture count, or -1 for regexp-mode routes (whose group values
  // come back as regexp_groups rather than slices).
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
      auto created = parse_list({c.pattern});
      ASSERT_TRUE(created.has_value()) << "pattern=" << c.pattern;
      it = lists.emplace(pattern, std::move(*created)).first;
    }
    const auto m = it->second.match(c.input);
    EXPECT_EQ(m.has_match(), c.matches)
        << "pattern=" << c.pattern << " input=" << c.input;
    if (c.matches) {
      // Rows without slice expectations are the regexp-mode routes: they
      // report the provider's groups, subset rows report slices.
      EXPECT_EQ(m.regexp_route, c.capture_count < 0)
          << "pattern=" << c.pattern << " input=" << c.input;
    }
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

TEST(url_pattern_list, witness_exhaustion_demotes_node) {
  // Nine 17-byte segments that differ only at byte 8: no witness plan over
  // the first/last 8 bytes plus the length can tell them apart, so the
  // offline search fails and the node dispatch demotes to a linear scan
  // (they also share a first byte, so the root index is not used). Matching
  // must not care.
  auto list = make_list({
      "/aaaaaaaaBaaaaaaaa",  // 0
      "/aaaaaaaaCaaaaaaaa",  // 1
      "/aaaaaaaaDaaaaaaaa",  // 2
      "/aaaaaaaaEaaaaaaab",  // 3
      "/aaaaaaaaFaaaaaaab",  // 4
      "/aaaaaaaaGaaaaaaab",  // 5
      "/aaaaaaaaHaaaaaaac",  // 6
      "/aaaaaaaaIaaaaaaac",  // 7
      "/aaaaaaaaJaaaaaaac",  // 8
  });
  EXPECT_EQ(list.match("/aaaaaaaaHaaaaaaac").route_index, 6);
  EXPECT_EQ(list.match("/aaaaaaaaJaaaaaaac").route_index, 8);
  EXPECT_EQ(list.match("/aaaaaaaaJaaaaaaab").route_index, -1);
  EXPECT_EQ(list.match("/aaaaaaaaBaaaaaaaa").route_index, 0);
  EXPECT_EQ(list.match("/aaaaaaaaCaaaaaaaa").route_index, 1);
  EXPECT_EQ(list.match("/aaaaaaaaDaaaaaaaa").route_index, 2);
  EXPECT_EQ(list.match("/aaaaaaaaEaaaaaaaa").route_index, -1);
  EXPECT_EQ(list.match("/aaaaaaaaBaaaaaaaZ").route_index, -1);
  EXPECT_EQ(list.match("/aaaaaaaaBaaaaaaa").route_index, -1);
}

TEST(url_pattern_list, witness_hostile_statics_before_params) {
  // The same 17-byte statics as leading segments of ":param" routes:
  // captures and misses stay exact through the direct-compare node.
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

TEST(url_pattern_list, witness_hostile_statics_share_a_first_byte) {
  // Routes 0 and 1 collide in every addressable byte while routes 2-6 differ
  // in one interior byte each; all seven share the first byte 'a' or 'b', so
  // the root index maps a run of children to direct compares.
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

TEST(url_pattern_list, single_character_statics_before_params) {
  // Single-character statics under the root index, each followed by a
  // param.
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

TEST(url_pattern_list, many_static_segments_before_a_param) {
  // Nine static segments and a trailing param: a deep chain of one-child
  // nodes ending in a pure-leaf param shortcut.
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

TEST(url_pattern_list, root_fanout_beyond_dispatch_table_capacity) {
  // 260 param routes under distinct first segments: more root children than
  // 8-bit slot ordinals can index (and more than max_direct_children per
  // first byte), so the root runs a linear scan.
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
  // More than 64 keys in one dispatch table (80 root children sharing the
  // first byte 'k', so the root index is not used): the multiplier search
  // starts with the loosened load factor.
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

TEST(url_pattern_list, huge_static_key) {
  // A 70000-byte static segment: the key lives in the blob (memcmp path)
  // and the 70001-byte input is beyond the fast-path length limit, so the
  // route answers through the sequential fallback.
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
      "/x/:y",  // 1
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
  // 17 to 24 segments are within the fast path but deeper than any pattern.
  std::string deep17 = "/x";
  for (int i = 1; i < 17; i++) {
    deep17 += "/s";
  }
  EXPECT_EQ(list.match(deep17).route_index, -1);
  EXPECT_EQ(list.match("/x/hit").route_index, 1);
}

TEST(url_pattern_list, param_then_static_routes_against_static_then_param) {
  // Routes with a leading param and routes with a leading static that
  // conflict at position 1 ("mm" vs "qq"): winners must be exactly the
  // specificity-order winners, with backtracking from the static child to
  // the param child.
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

TEST(url_pattern_list, overlapping_param_routes_keep_specificity_order) {
  // Three route shapes of three segments that can all match one pathname
  // ("q" at position 1 is shared): the specificity order must decide, with
  // the walk backtracking through every alternative.
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
  EXPECT_FALSE(parse_list({"/users/(unclosed"}).has_value());
  // A '?' modifier cannot follow plain text.
  EXPECT_FALSE(parse_list({"/a?b"}).has_value());
  // Duplicate group name within one pattern is a URLPattern type error.
  auto dup = parse_list({"/:id/:id"});
  ASSERT_FALSE(dup.has_value());
  EXPECT_EQ(dup.error(), ada::errors::type_error);
  // Tokenizes fine but the generated regex is rejected by the provider
  // (invalid interval), which create must surface as the same error.
  auto bad_regex = parse_list({"/(a{2,1})"});
  ASSERT_FALSE(bad_regex.has_value());
  EXPECT_EQ(bad_regex.error(), ada::errors::type_error);
  // One bad pattern anywhere fails the whole list.
  EXPECT_FALSE(parse_list({"/fine", "/also/:ok", "/(a{2,1})"}).has_value());
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

  // Regexp routes surface their names and the provider's group values, in
  // the same order.
  auto r = list.match("/users/123");
  EXPECT_EQ(r.route_index, 5);
  EXPECT_EQ(r.capture_count, 0u);
  EXPECT_TRUE(r.regexp_route);
  ASSERT_EQ(r.regexp_groups.size(), 1u);
  EXPECT_EQ(r.regexp_groups[0], std::optional<std::string>("123"));
  auto h = list.match("/@bob/x-hello");
  EXPECT_EQ(h.route_index, 6);
  ASSERT_EQ(h.regexp_groups.size(), 2u);
  EXPECT_EQ(h.regexp_groups[0], std::optional<std::string>("bob"));
  EXPECT_EQ(h.regexp_groups[1], std::optional<std::string>("hello"));
}

// ---------------------------------------------------------------------------
// Provider, options and input-shape tests: the list must use the regex
// provider exactly as url_pattern does (create_instance with ignore_case,
// regex_search for group values), accept url_pattern_options and
// url_pattern objects, and prune the auxiliary routes it does not need.

namespace {

// A provider wrapper that counts its calls and records the ignore_case flag
// it was given, delegating to std_regex_provider.
struct counting_provider {
  using regex_type = regex_provider::regex_type;
  static inline size_t create_instance_calls = 0;
  static inline size_t regex_search_calls = 0;
  static inline size_t regex_match_calls = 0;
  static inline bool last_ignore_case = false;
  static void reset() {
    create_instance_calls = 0;
    regex_search_calls = 0;
    regex_match_calls = 0;
    last_ignore_case = false;
  }
  static std::optional<regex_type> create_instance(std::string_view pattern,
                                                   bool ignore_case) {
    create_instance_calls++;
    last_ignore_case = ignore_case;
    return regex_provider::create_instance(pattern, ignore_case);
  }
  static std::optional<std::vector<std::optional<std::string>>> regex_search(
      std::string_view input, const regex_type& pattern) {
    regex_search_calls++;
    return regex_provider::regex_search(input, pattern);
  }
  static bool regex_match(std::string_view input, const regex_type& pattern) {
    regex_match_calls++;
    return regex_provider::regex_match(input, pattern);
  }
};
static_assert(ada::url_pattern_regex::regex_concept<counting_provider>);

using counting_list = ada::url_pattern_list<counting_provider>;

tl::expected<counting_list, ada::errors> parse_counting(
    const std::vector<std::string_view>& patterns,
    const ada::url_pattern_options* options = nullptr) {
  return ada::parse_url_pattern_list<counting_provider>(patterns, nullptr,
                                                        options);
}

std::optional<std::string> group(const char* s) { return std::string(s); }

}  // namespace

TEST(url_pattern_list, custom_provider_is_used_for_regexp_routes) {
  counting_provider::reset();
  auto list = parse_counting({
      "/users/(\\d+)",    // 0: regexp, compiled through the provider
      "/users/:id",       // 1: subset, no provider involvement
      "/files/*",         // 2: subset
      "/@:handle/(\\w+)"  // 3: regexp
  });
  ASSERT_TRUE(list.has_value());
  // One create_instance per regexp route; subset routes never touch the
  // provider.
  EXPECT_EQ(counting_provider::create_instance_calls, 2u);
  EXPECT_FALSE(counting_provider::last_ignore_case);

  // A regexp winner is tested with regex_match and its groups then come
  // from regex_search (as url_pattern::exec obtains them).
  counting_provider::reset();
  auto m = list->match("/users/123");
  EXPECT_EQ(m.route_index, 0);  // outranks "/users/:id" on insertion order
  EXPECT_TRUE(m.regexp_route);
  ASSERT_EQ(m.regexp_groups.size(), 1u);
  EXPECT_EQ(m.regexp_groups[0], group("123"));
  EXPECT_EQ(counting_provider::regex_search_calls, 1u);
  EXPECT_EQ(counting_provider::regex_match_calls, 1u);

  // A fast-path miss scans the auxiliary routes, but a route whose literal
  // prefix ("users") cannot fit the input is skipped before the provider.
  counting_provider::reset();
  auto h = list->match("/@bob/hello");
  EXPECT_EQ(h.route_index, 3);
  ASSERT_EQ(h.regexp_groups.size(), 2u);
  EXPECT_EQ(h.regexp_groups[0], group("bob"));
  EXPECT_EQ(h.regexp_groups[1], group("hello"));
  EXPECT_EQ(counting_provider::regex_match_calls, 1u);
  EXPECT_EQ(counting_provider::regex_search_calls, 1u);

  // A subset winner that nothing outranks never runs the provider.
  counting_provider::reset();
  auto f = list->match("/files/a/b");
  EXPECT_EQ(f.route_index, 2);
  EXPECT_FALSE(f.regexp_route);
  EXPECT_EQ(counting_provider::regex_search_calls, 0u);
  EXPECT_EQ(counting_provider::regex_match_calls, 0u);
}

TEST(url_pattern_list, regexp_groups_report_unmatched_optional_groups) {
  auto list = make_list({"/users/:id?"});
  auto with = list.match("/users/7");
  EXPECT_EQ(with.route_index, 0);
  EXPECT_TRUE(with.regexp_route);
  ASSERT_EQ(with.regexp_groups.size(), 1u);
  EXPECT_EQ(with.regexp_groups[0], group("7"));
  auto without = list.match("/users");
  EXPECT_EQ(without.route_index, 0);
  ASSERT_EQ(without.regexp_groups.size(), 1u);
  EXPECT_EQ(without.regexp_groups[0], std::nullopt);
  EXPECT_EQ(list.group_names(0), std::vector<std::string>{"id"});
}

TEST(url_pattern_list, auxiliary_routes_are_pruned_after_a_fast_path_hit) {
  // A regexp route that outranks a compiled winner (same kind sequence,
  // earlier insertion, compatible literal prefix) must still be tested; one
  // that cannot outrank the winner, or cannot match the same input, must
  // not cost a regex execution.
  {
    counting_provider::reset();
    auto list = parse_counting({
        "/users/(\\d+)",  // 0: outranks route 1 on insertion order
        "/users/:id",     // 1
        "/posts/(\\d+)",  // 2: literal "posts" can never match "/users/..."
    });
    ASSERT_TRUE(list.has_value());
    counting_provider::reset();
    auto digits = list->match("/users/123");
    EXPECT_EQ(digits.route_index, 0);
    EXPECT_EQ(counting_provider::regex_match_calls, 1u);  // route 0 only
    EXPECT_EQ(counting_provider::regex_search_calls, 1u);
    counting_provider::reset();
    auto name = list->match("/users/bob");
    EXPECT_EQ(name.route_index, 1);
    ASSERT_EQ(name.capture_count, 1u);
    EXPECT_EQ(capture_text("/users/bob", name, 0), "bob");
    EXPECT_EQ(counting_provider::regex_match_calls, 1u);  // route 0 only
    EXPECT_EQ(counting_provider::regex_search_calls, 0u);
    counting_provider::reset();
    auto post = list->match("/posts/9");
    EXPECT_EQ(post.route_index, 2);  // fast-path miss: aux routes scanned
    EXPECT_EQ(counting_provider::regex_match_calls, 1u);  // route 2 only
    EXPECT_EQ(counting_provider::regex_search_calls, 1u);
  }
  {
    counting_provider::reset();
    auto list = parse_counting({
        "/users/:id",     // 0
        "/users/(\\d+)",  // 1: same kind sequence, later: never outranks 0
        "/(\\d+)/edit",   // 2: kinds [param, literal]: outranked by 0
    });
    ASSERT_TRUE(list.has_value());
    counting_provider::reset();
    auto m = list->match("/users/123");
    EXPECT_EQ(m.route_index, 0);
    EXPECT_FALSE(m.regexp_route);
    EXPECT_EQ(counting_provider::regex_search_calls, 0u);
    EXPECT_EQ(counting_provider::regex_match_calls, 0u);
    EXPECT_EQ(list->match("/7/edit").route_index, 2);
  }
  {
    // A static winner is outranked by nothing: no regex ever runs after a
    // static hit, whatever the regexp routes look like.
    counting_provider::reset();
    auto list = parse_counting({"/(.*)", "/health", "/users/(\\d+)"});
    ASSERT_TRUE(list.has_value());
    counting_provider::reset();
    EXPECT_EQ(list->match("/health").route_index, 1);
    EXPECT_EQ(counting_provider::regex_search_calls, 0u);
    EXPECT_EQ(list->match("/other").route_index, 0);
  }
}

TEST(url_pattern_list, ignore_case_option_subset_routes) {
  const ada::url_pattern_options options{.ignore_case = true};
  auto list = make_list(
      {
          "/Users/:id",     // 0
          "/About",         // 1
          "/Files/*",       // 2
          "/API/v1/:a/:b",  // 3
      },
      &options);
  EXPECT_TRUE(list.ignore_case());
  for (const char* input : {"/users/42", "/USERS/42", "/Users/42"}) {
    auto m = list.match(input);
    EXPECT_EQ(m.route_index, 0) << input;
    ASSERT_EQ(m.capture_count, 1u) << input;
    // Captures slice the original input, not a folded copy.
    EXPECT_EQ(capture_text(input, m, 0), "42") << input;
  }
  EXPECT_EQ(list.match("/about").route_index, 1);
  EXPECT_EQ(list.match("/ABOUT").route_index, 1);
  EXPECT_EQ(list.match("/abut").route_index, -1);
  auto w = list.match("/FILES/A/B");
  EXPECT_EQ(w.route_index, 2);
  ASSERT_EQ(w.capture_count, 1u);
  EXPECT_EQ(capture_text("/FILES/A/B", w, 0), "A/B");
  auto d = list.match("/api/V1/X/y");
  EXPECT_EQ(d.route_index, 3);
  ASSERT_EQ(d.capture_count, 2u);
  EXPECT_EQ(capture_text("/api/V1/X/y", d, 0), "X");
  EXPECT_EQ(capture_text("/api/V1/X/y", d, 1), "y");
  // Case-sensitive by default.
  auto strict = make_list({"/Users/:id"});
  EXPECT_FALSE(strict.ignore_case());
  EXPECT_EQ(strict.match("/users/42").route_index, -1);
  EXPECT_EQ(strict.match("/Users/42").route_index, 0);
  // Beyond the fast-path length the sequential fallback folds on the fly.
  std::string longu = "/FILES/" + std::string(5000, 'X');
  auto l = list.match(longu);
  EXPECT_EQ(l.route_index, 2);
  ASSERT_EQ(l.capture_count, 1u);
  EXPECT_EQ(l.captures[0].length, 5000u);
}

TEST(url_pattern_list, ignore_case_agrees_with_url_pattern) {
  const ada::url_pattern_options options{.ignore_case = true};
  const std::vector<std::string_view> patterns = {
      "/Users/:id", "/About", "/Files/*", "/a/B/c", "/x-(\\d+)/Y", "/Q/:p?"};
  const std::vector<std::string_view> inputs = {
      "/users/1", "/USERS/1", "/about", "/ABOUT/", "/files/X", "/A/b/C",
      "/a/b/c/",  "/x-7/y",   "/X-7/Y", "/x-a/y",  "/q",       "/Q/z"};
  for (const std::string_view pattern : patterns) {
    auto list = make_list({pattern}, &options);
    auto url_pattern = ada::parse_url_pattern<regex_provider>(
        ada::url_pattern_init{.pathname = std::string(pattern)}, nullptr,
        &options);
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

TEST(url_pattern_list, ignore_case_reaches_the_provider) {
  const ada::url_pattern_options options{.ignore_case = true};
  counting_provider::reset();
  auto list = parse_counting({"/Docs/(\\d+)", "/users/:id"}, &options);
  ASSERT_TRUE(list.has_value());
  EXPECT_EQ(counting_provider::create_instance_calls, 1u);
  EXPECT_TRUE(counting_provider::last_ignore_case);
  auto m = list->match("/DOCS/12");
  EXPECT_EQ(m.route_index, 0);
  ASSERT_EQ(m.regexp_groups.size(), 1u);
  EXPECT_EQ(m.regexp_groups[0], group("12"));
  // Duplicate patterns under folding collapse onto the smaller index.
  auto dup = make_list({"/Users/:id", "/users/:id"}, &options);
  EXPECT_EQ(dup.match("/USERS/1").route_index, 0);
}

TEST(url_pattern_list, parse_url_pattern_list_free_function) {
  const std::vector<std::string_view> patterns = {"/", "/users/:id",
                                                  "/files/*"};
  auto list = ada::parse_url_pattern_list<regex_provider>(patterns);
  ASSERT_TRUE(list.has_value());
  EXPECT_EQ(list->size(), 3u);
  EXPECT_EQ(list->match("/users/1").route_index, 1);
  EXPECT_EQ(list->pattern(1), "/users/:id");
  // Errors surface exactly as from the URLPattern constructor.
  auto bad = ada::parse_url_pattern_list<regex_provider>(
      std::vector<std::string_view>{"/fine", "/(a{2,1})"});
  ASSERT_FALSE(bad.has_value());
  EXPECT_EQ(bad.error(), ada::errors::type_error);
  // An empty span is an empty list.
  auto empty = ada::parse_url_pattern_list<regex_provider>(
      std::span<const std::string_view>{});
  ASSERT_TRUE(empty.has_value());
  EXPECT_EQ(empty->size(), 0u);
}

TEST(url_pattern_list, parse_url_pattern_list_with_base_url) {
  // With a base URL, each pattern is processed as the pathname of a
  // URLPatternInit: relative patterns resolve against the base's path.
  const std::string_view base = "https://example.com/app/index.html";
  const std::vector<std::string_view> patterns = {"users/:id", "/abs",
                                                  "./rel/*"};
  auto list = ada::parse_url_pattern_list<regex_provider>(patterns, &base);
  ASSERT_TRUE(list.has_value());
  EXPECT_EQ(list->pattern(0), "/app/users/:id");
  EXPECT_EQ(list->pattern(1), "/abs");
  EXPECT_EQ(list->pattern(2), "/app/./rel/*");
  auto m = list->match("/app/users/7");
  EXPECT_EQ(m.route_index, 0);
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(capture_text("/app/users/7", m, 0), "7");
  EXPECT_EQ(list->match("/abs").route_index, 1);
  EXPECT_EQ(list->match("/users/7").route_index, -1);
  // The same processing url_pattern applies to a relative pattern string.
  auto up = ada::parse_url_pattern<regex_provider>("users/:id", &base);
  ASSERT_TRUE(up.has_value());
  EXPECT_EQ(up->get_pathname(), list->pattern(0));
  // An unparsable base URL is a type error, as for parse_url_pattern.
  const std::string_view bad_base = "not a url";
  auto bad = ada::parse_url_pattern_list<regex_provider>(patterns, &bad_base);
  ASSERT_FALSE(bad.has_value());
  EXPECT_EQ(bad.error(), ada::errors::type_error);
}

TEST(url_pattern_list, url_pattern_objects_as_input) {
  std::vector<ada::url_pattern<regex_provider>> patterns;
  for (const char* pathname :
       {"/", "/users/:id", "/users/(\\d+)", "/files/*", "/:a/x-(\\w+)"}) {
    auto parsed = ada::parse_url_pattern<regex_provider>(
        ada::url_pattern_init{.pathname = pathname});
    ASSERT_TRUE(parsed.has_value()) << pathname;
    patterns.push_back(std::move(*parsed));
  }
  auto list = ada::parse_url_pattern_list<regex_provider>(
      std::span<const ada::url_pattern<regex_provider>>(patterns));
  ASSERT_TRUE(list.has_value());
  ASSERT_EQ(list->size(), 5u);
  for (size_t i = 0; i < patterns.size(); i++) {
    EXPECT_EQ(list->pattern(i), patterns[i].get_pathname());
  }
  EXPECT_EQ(list->match("/").route_index, 0);
  auto m = list->match("/users/bob");
  EXPECT_EQ(m.route_index, 1);
  ASSERT_EQ(m.capture_count, 1u);
  EXPECT_EQ(capture_text("/users/bob", m, 0), "bob");
  // Regexp routes reuse the pattern's compiled pathname component and
  // report its groups.
  auto d = list->match("/users/42");
  EXPECT_EQ(d.route_index, 1);  // "/users/:id" wins the tie on insertion
  auto w = list->match("/left/x-right");
  EXPECT_EQ(w.route_index, 4);
  EXPECT_TRUE(w.regexp_route);
  EXPECT_EQ(list->group_names(4), (std::vector<std::string>{"a", "0"}));
  ASSERT_EQ(w.regexp_groups.size(), 2u);
  EXPECT_EQ(w.regexp_groups[0], group("left"));
  EXPECT_EQ(w.regexp_groups[1], group("right"));
  // The url_pattern's own exec agrees on the groups.
  auto exec =
      patterns[4].exec(ada::url_pattern_init{.pathname = "/left/x-right"});
  ASSERT_TRUE(exec.has_value() && exec->has_value());
  EXPECT_EQ((*exec)->pathname.groups.at("a"), group("left"));
  EXPECT_EQ((*exec)->pathname.groups.at("0"), group("right"));
}

TEST(url_pattern_list, url_pattern_objects_carry_ignore_case) {
  const ada::url_pattern_options options{.ignore_case = true};
  std::vector<ada::url_pattern<regex_provider>> patterns;
  for (const char* pathname : {"/Users/:id", "/Docs/(\\d+)"}) {
    auto parsed = ada::parse_url_pattern<regex_provider>(
        ada::url_pattern_init{.pathname = pathname}, nullptr, &options);
    ASSERT_TRUE(parsed.has_value()) << pathname;
    patterns.push_back(std::move(*parsed));
  }
  auto list = ada::parse_url_pattern_list<regex_provider>(
      std::span<const ada::url_pattern<regex_provider>>(patterns));
  ASSERT_TRUE(list.has_value());
  EXPECT_TRUE(list->ignore_case());
  EXPECT_EQ(list->match("/users/1").route_index, 0);
  auto d = list->match("/docs/9");
  EXPECT_EQ(d.route_index, 1);
  ASSERT_EQ(d.regexp_groups.size(), 1u);
  EXPECT_EQ(d.regexp_groups[0], group("9"));
  // Mixed flags cannot share one list.
  auto strict = ada::parse_url_pattern<regex_provider>(
      ada::url_pattern_init{.pathname = "/x"});
  ASSERT_TRUE(strict.has_value());
  patterns.push_back(std::move(*strict));
  auto mixed = ada::parse_url_pattern_list<regex_provider>(
      std::span<const ada::url_pattern<regex_provider>>(patterns));
  ASSERT_FALSE(mixed.has_value());
  EXPECT_EQ(mixed.error(), ada::errors::type_error);
}

// ---------------------------------------------------------------------------
// Matcher-internal sweeps: the SWAR segment scan, short-tail compares and
// the root first-byte index.

namespace {

std::vector<uint16_t> naive_segment_starts(std::string_view url) {
  std::vector<uint16_t> starts{1};
  for (size_t i = 1; i < url.size(); i++) {
    if (url[i] == '/') {
      starts.push_back(static_cast<uint16_t>(i + 1));
    }
  }
  return starts;
}

}  // namespace

TEST(url_pattern_list, swar_segment_scan_sweep) {
  namespace detail = ada::url_pattern_list_detail;
  using ada::url_pattern_list_limits::max_fast_path_segments;
  std::mt19937_64 rng(0x5CA7ull);
  // Filler bytes include values >= 0x80, the byte that differs from '/'
  // only in the high bit (which must never read as a separator), and the
  // two line terminators, which the scan treats as ordinary bytes.
  const unsigned char fillers[] = {'a',  'z',  '0',  0x80, 0xAF,
                                   0xFF, 0x2E, 0x30, '\n', '\r'};
  for (uint32_t len = 1; len <= 70; len++) {
    for (int variant = 0; variant < 12; variant++) {
      std::string url(len, 'a');
      url[0] = '/';
      for (uint32_t i = 1; i < len; i++) {
        url[i] = static_cast<char>(fillers[rng() % 10]);
      }
      // Slash placements: none, every position, first/last, random.
      if (variant == 1) {
        for (uint32_t i = 1; i < len; i++) {
          url[i] = '/';
        }
      } else if (variant == 2 && len > 1) {
        url[1] = '/';
      } else if (variant == 3 && len > 1) {
        url[len - 1] = '/';
      } else if (variant >= 4) {
        const uint32_t n_slashes = static_cast<uint32_t>(rng() % 6);
        for (uint32_t k = 0; k < n_slashes && len > 1; k++) {
          url[1 + rng() % (len - 1)] = '/';
        }
      }
      const std::vector<uint16_t> expected = naive_segment_starts(url);
      uint16_t soff[max_fast_path_segments + 1];
      const uint32_t nseg = detail::scan_segments(
          url.data(), static_cast<uint32_t>(url.size()), soff);
      if (expected.size() > max_fast_path_segments) {
        EXPECT_EQ(nseg, 0u) << "len=" << len << " variant=" << variant;
        continue;
      }
      ASSERT_EQ(nseg, expected.size())
          << "len=" << len << " variant=" << variant;
      for (uint32_t i = 0; i < nseg; i++) {
        EXPECT_EQ(soff[i], expected[i])
            << "len=" << len << " variant=" << variant << " i=" << i;
      }
      EXPECT_EQ(soff[nseg], len + 1);
    }
  }
}

TEST(url_pattern_list, short_tail_segments_compare_exactly) {
  // Final segments of 1..7 bytes are compared without loading past the end
  // of the input; a mismatch in the last byte, an extra byte, or a missing
  // byte must all be rejected.
  std::vector<std::string> storage;
  for (uint32_t len = 1; len <= 7; len++) {
    storage.push_back("/t/" + std::string(len, 'x'));      // 0,2,...: static
    storage.push_back("/p/:id/" + std::string(len, 'y'));  // after a param
  }
  std::vector<std::string_view> patterns(storage.begin(), storage.end());
  auto list = make_list(patterns);
  for (uint32_t len = 1; len <= 7; len++) {
    const int32_t route = static_cast<int32_t>((len - 1) * 2);
    const std::string hit = "/t/" + std::string(len, 'x');
    EXPECT_EQ(list.match(hit).route_index, route) << len;
    std::string last_differs = hit;
    last_differs.back() = 'X';
    EXPECT_EQ(list.match(last_differs).route_index, -1) << len;
    EXPECT_EQ(list.match(hit + "x").route_index, len < 7 ? route + 2 : -1)
        << len;
    EXPECT_EQ(list.match(hit + "/").route_index, -1) << len;
    const std::string after_param = "/p/42/" + std::string(len, 'y');
    auto m = list.match(after_param);
    EXPECT_EQ(m.route_index, route + 1) << len;
    ASSERT_EQ(m.capture_count, 1u) << len;
    EXPECT_EQ(capture_text(after_param, m, 0), "42") << len;
    std::string wrong = after_param;
    wrong.back() = 'Y';
    EXPECT_EQ(list.match(wrong).route_index, -1) << len;
  }
  // Short non-final segments (8 readable bytes available) take the masked
  // whole-word compare; they must reject on every byte too.
  auto mid = make_list({"/ab/cd/efgh/i", "/ab/cX/efgh/i"});
  EXPECT_EQ(mid.match("/ab/cd/efgh/i").route_index, 0);
  EXPECT_EQ(mid.match("/ab/cX/efgh/i").route_index, 1);
  EXPECT_EQ(mid.match("/ab/cdd/efgh/i").route_index, -1);
  EXPECT_EQ(mid.match("/aX/cd/efgh/i").route_index, -1);
}

TEST(url_pattern_list, root_first_byte_index) {
  // Routes differing only after byte 0, several sharing a first byte, and
  // first bytes with no route at all.
  auto list = make_list({
      "/users",      // 0
      "/uploads",    // 1
      "/u",          // 2
      "/user",       // 3
      "/posts",      // 4
      "/p",          // 5
      "/health",     // 6
      "/users/:id",  // 7
      "/x/*",        // 8
  });
  EXPECT_EQ(list.match("/users").route_index, 0);
  EXPECT_EQ(list.match("/uploads").route_index, 1);
  EXPECT_EQ(list.match("/u").route_index, 2);
  EXPECT_EQ(list.match("/user").route_index, 3);
  EXPECT_EQ(list.match("/posts").route_index, 4);
  EXPECT_EQ(list.match("/p").route_index, 5);
  EXPECT_EQ(list.match("/health").route_index, 6);
  EXPECT_EQ(list.match("/users/9").route_index, 7);
  EXPECT_EQ(list.match("/x/a/b").route_index, 8);
  EXPECT_EQ(list.match("/uu").route_index, -1);
  EXPECT_EQ(list.match("/zzz").route_index, -1);
  EXPECT_EQ(list.match("/").route_index, -1);
  EXPECT_EQ(list.match("/upload").route_index, -1);
  EXPECT_EQ(list.match("/User").route_index, -1);
  // More than max_direct_children children sharing one first byte: the
  // index is not used and the root falls back to the projection ladder.
  std::vector<std::string> storage;
  for (int i = 0; i < 20; i++) {
    storage.push_back("/same" + std::to_string(i));
  }
  storage.push_back("/other");
  std::vector<std::string_view> patterns(storage.begin(), storage.end());
  auto wide = make_list(patterns);
  EXPECT_EQ(wide.match("/same7").route_index, 7);
  EXPECT_EQ(wide.match("/same19").route_index, 19);
  EXPECT_EQ(wide.match("/other").route_index, 20);
  EXPECT_EQ(wide.match("/same20").route_index, -1);
}

TEST(url_pattern_list, direct_compare_fanout_up_to_eight) {
  // A non-root node with up to 8 static children compares them directly;
  // nine children switch to projection. Both must answer identically.
  for (int fanout : {3, 8, 9, 16}) {
    std::vector<std::string> storage;
    for (int i = 0; i < fanout; i++) {
      storage.push_back("/api/child" + std::to_string(i));
    }
    storage.push_back("/api/:rest");
    std::vector<std::string_view> patterns(storage.begin(), storage.end());
    auto list = make_list(patterns);
    for (int i = 0; i < fanout; i++) {
      EXPECT_EQ(list.match("/api/child" + std::to_string(i)).route_index, i)
          << fanout;
    }
    EXPECT_EQ(list.match("/api/child" + std::to_string(fanout)).route_index,
              fanout)
        << fanout;  // the param route
    EXPECT_EQ(list.match("/api/child0/x").route_index, -1) << fanout;
  }
}

TEST(url_pattern_list, regexp_route_shape_check_precedes_the_provider) {
  // A regexp route made only of fixed text and ":name" groups has an exact
  // segment count and exact literal positions: inputs that cannot fit it
  // are rejected before any provider call, even on the "/*" hits that it
  // outranks.
  counting_provider::reset();
  auto list = parse_counting({"/@:handle/status/:sid", "/*"});
  ASSERT_TRUE(list.has_value());
  counting_provider::reset();
  EXPECT_EQ(list->match("/a/b").route_index, 1);  // 2 segments: never
  EXPECT_EQ(list->match("/a/b/c/d").route_index, 1);
  EXPECT_EQ(list->match("/a/nope/c").route_index, 1);   // literal mismatch
  EXPECT_EQ(list->match("/a/status/").route_index, 1);  // empty ":sid"
  EXPECT_EQ(counting_provider::regex_match_calls, 0u);
  EXPECT_EQ(counting_provider::regex_search_calls, 0u);
  // The shape fits but the regex does not: one regex_match, no search.
  counting_provider::reset();
  EXPECT_EQ(list->match("/x/status/y").route_index, 1);
  EXPECT_EQ(counting_provider::regex_match_calls, 1u);
  EXPECT_EQ(counting_provider::regex_search_calls, 0u);
  // A hit: regex_match then regex_search for the groups.
  counting_provider::reset();
  auto m = list->match("/@bob/status/77");
  EXPECT_EQ(m.route_index, 0);
  ASSERT_EQ(m.regexp_groups.size(), 2u);
  EXPECT_EQ(m.regexp_groups[0], group("bob"));
  EXPECT_EQ(m.regexp_groups[1], group("77"));
  EXPECT_EQ(counting_provider::regex_match_calls, 1u);
  EXPECT_EQ(counting_provider::regex_search_calls, 1u);
  // A custom group may span segments, so only the literal prefix before it
  // is trusted: "/a/x/y/edit" must still reach the provider.
  auto custom = make_list({"/a/(.*)/edit", "/*"});
  EXPECT_EQ(custom.match("/a/x/y/edit").route_index, 0);
  EXPECT_EQ(custom.match("/b/x/edit").route_index, 1);
  // Not anchored at '/': nothing is assumed about the shape.
  auto loose = make_list({"(.*)", "/*"});
  EXPECT_EQ(loose.match("/anything/at/all").route_index, 0);
}

TEST(url_pattern_list, wildcard_does_not_match_line_terminators) {
  // "*" stands for "(.*)" in the URLPattern regexp, and "." does not match
  // a line terminator, while ":param" ("[^/]+?") does. Canonical pathnames
  // contain neither LF nor CR; this pins the rule for raw inputs.
  const std::vector<std::string_view> patterns = {"/files/*", "/:name", "/*"};
  auto list = make_list(patterns);
  std::vector<ada::url_pattern<regex_provider>> objects;
  for (std::string_view pattern : patterns) {
    auto parsed = ada::parse_url_pattern<regex_provider>(
        ada::url_pattern_init{.pathname = std::string(pattern)});
    ASSERT_TRUE(parsed.has_value());
    objects.push_back(std::move(*parsed));
  }
  const auto any_url_pattern_matches = [&](std::string_view input) {
    for (const auto& object : objects) {
      if (object.pathname_component.fast_match(input)) {
        return true;
      }
    }
    return false;
  };
  EXPECT_EQ(list.match("/files/a/b").route_index, 0);
  EXPECT_EQ(list.match("/files/").route_index, 0);
  EXPECT_EQ(list.match("/files/a\nb").route_index, -1);
  EXPECT_EQ(list.match("/files/\r").route_index, -1);
  EXPECT_EQ(list.match("/a\r/b").route_index, -1);
  EXPECT_EQ(list.match("/x\ny").route_index, 1);  // "[^/]+?" matches LF
  EXPECT_EQ(list.match("/%0A").route_index, 1);   // the canonical form
  for (std::string_view input :
       {"/files/a/b", "/files/", "/files/a\nb", "/files/\r", "/a\r/b", "/x\ny",
        "/\n", "/%0A", "/files/a%0Ab"}) {
    EXPECT_EQ(list.match(input).has_match(), any_url_pattern_matches(input))
        << input;
  }
  // The same rule in the sequential matcher (a 17-segment route is beyond
  // the trie limit).
  std::string deep;
  for (int i = 0; i < 16; i++) {
    deep += "/s" + std::to_string(i);
  }
  const std::string deep_wildcard = deep + "/*";
  auto sequential = make_list({deep_wildcard});
  EXPECT_EQ(sequential.match(deep + "/x/y").route_index, 0);
  EXPECT_EQ(sequential.match(deep + "/").route_index, 0);
  EXPECT_EQ(sequential.match(deep + "/x\ny").route_index, -1);
  EXPECT_EQ(sequential.match(deep + "/\r").route_index, -1);
}

TEST(url_pattern_list, wildcard_tail_check_covers_every_length) {
  // The wildcard tail check works 8 bytes at a time: a terminator at every
  // position of tails from 1 to 40 bytes must be seen, and tails without
  // one (including bytes >= 0x80 and other control bytes) must pass.
  auto list = make_list({"/files/*"});
  for (uint32_t n = 1; n <= 40; n++) {
    std::string clean = "/files/" + std::string(n, 'x');
    clean[7 + n / 2] = static_cast<char>(0xC3);  // a non-ASCII byte
    if (n > 2) {
      clean[8] = '\t';  // a control byte that is not a terminator
    }
    EXPECT_EQ(list.match(clean).route_index, 0) << n;
    for (uint32_t at = 0; at < n; at++) {
      std::string url = "/files/" + std::string(n, 'x');
      url[7 + at] = (at % 2) ? '\n' : '\r';
      EXPECT_EQ(list.match(url).route_index, -1) << n << " " << at;
    }
  }
}

TEST(url_pattern_list, inputs_need_no_terminator) {
  // match() reads exactly the bytes of the view it is given: a pathname in an
  // exactly sized heap buffer, with no terminator after it, is matched like
  // any other (a read past its end is a heap-buffer-overflow under ASan).
  const auto exact = [](const list_type& list, std::string_view input) {
    const std::vector<char> buffer(input.begin(), input.end());
    return list.match(std::string_view(buffer.data(), buffer.size()))
        .route_index;
  };
  auto list = make_list(
      {"/", "/users/:id", "/users/me", "/posts", "/about/*", "/a/b/c/d/e/f/g"});
  EXPECT_EQ(exact(list, "/"), 0);
  EXPECT_EQ(exact(list, "/users/42"), 1);
  EXPECT_EQ(exact(list, "/users/me"), 2);
  EXPECT_EQ(exact(list, "/posts"), 3);
  EXPECT_EQ(exact(list, "/about/x/y"), 4);
  EXPECT_EQ(exact(list, "/a/b/c/d/e/f/g"), 5);
  EXPECT_EQ(exact(list, "/a/b/c/d/e/f/gh"), -1);
  EXPECT_EQ(exact(list, "/users/"), -1);
  EXPECT_EQ(exact(list, "//"), -1);
  EXPECT_EQ(exact(list, ""), -1);
  // A root with the first-byte index (three or more children, none with an
  // empty key) probed with empty segments: "/" has no first byte to index.
  auto indexed = make_list({"/users/:id", "/users/me", "/posts", "/about/*"});
  EXPECT_EQ(exact(indexed, "/"), -1);
  EXPECT_EQ(exact(indexed, "//"), -1);
  EXPECT_EQ(exact(indexed, "/users/"), -1);
  EXPECT_EQ(exact(indexed, "/posts/"), -1);
  EXPECT_EQ(exact(indexed, "/p"), -1);
  EXPECT_EQ(exact(indexed, "/posts"), 2);
}
