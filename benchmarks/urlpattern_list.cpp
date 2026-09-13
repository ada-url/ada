// Benchmark: routing a pathname over ~100 routes, comparing the current
// URLPattern reality (a sequential url_pattern::exec loop) against the
// compiled ada::url_pattern_list. Run with ADA_BENCHMARKS=ON and
// ADA_USE_UNSAFE_STD_REGEX_PROVIDER=ON, in Release mode.
#include "benchmark_header.h"

using regex_provider = ada::url_pattern_regex::std_regex_provider;
using list_type = ada::url_pattern_list<regex_provider>;

// ---- a realistic REST route table (static -> param -> wildcard, so that
// insertion-order first match and specificity order agree and the two
// implementations can be cross-checked for identical answers) ---------------

static const std::vector<std::string>& route_table() {
  static const std::vector<std::string> routes = [] {
    std::vector<std::string> r;
    static const char* resources[] = {
        "users",    "orders",  "products", "invoices", "teams",
        "projects", "tickets", "sessions", "webhooks", "reports"};
    // 41 static routes.
    r.push_back("/");
    r.push_back("/health");
    r.push_back("/metrics");
    r.push_back("/login");
    r.push_back("/logout");
    r.push_back("/settings/profile");
    for (const char* res : resources) {
      r.push_back(std::string("/api/v1/") + res);
      r.push_back(std::string("/api/v1/") + res + "/count");
      r.push_back(std::string("/admin/") + res);
    }
    r.push_back("/api/v1/users/me");
    r.push_back("/api/v1/users/me/preferences");
    r.push_back("/api/v2/users");
    r.push_back("/api/v2/orders");
    r.push_back("/api/v2/products");
    // 52 parameterized routes.
    for (const char* res : resources) {
      r.push_back(std::string("/api/v1/") + res + "/:id");
      r.push_back(std::string("/api/v1/") + res + "/:id/history");
      r.push_back(std::string("/admin/") + res + "/:id");
    }
    r.push_back("/api/v1/users/:id/posts/:post_id");
    r.push_back("/api/v1/users/:id/posts/:post_id/comments");
    r.push_back("/api/v1/orders/:id/items/:item_id");
    r.push_back("/api/v1/teams/:team_id/members/:member_id");
    r.push_back("/api/v1/projects/:project_id/tickets/:ticket_id");
    r.push_back("/api/v2/users/:id");
    r.push_back("/api/v2/orders/:id");
    r.push_back("/blog/:year/:month/:slug");
    r.push_back("/docs/:section/:page");
    r.push_back("/orgs/:org/repos/:repo/issues/:number");
    r.push_back("/orgs/:org/repos/:repo/pulls/:number");
    r.push_back("/u/:username");
    r.push_back("/t/:tag");
    r.push_back("/search/:query");
    r.push_back("/shorturl/:code");
    r.push_back("/@:handle/status/:status_id");
    r.push_back("/w/:lang/wiki/:title");
    r.push_back("/cdn/:region/:bucket/:object");
    r.push_back("/v/:video_id");
    r.push_back("/c/:channel/videos");
    r.push_back("/api/v1/webhooks/:id/deliveries");
    r.push_back("/api/v1/reports/:id/export");
    r.push_back("/oauth/:provider/callback");
    // 7 wildcard routes.
    r.push_back("/static/*");
    r.push_back("/assets/js/*");
    r.push_back("/assets/css/*");
    r.push_back("/files/*");
    r.push_back("/downloads/*");
    r.push_back("/proxy/api/*");
    r.push_back("/*");
    return r;
  }();
  return routes;
}

// The same table with one regexp route added, the way a real table grows:
// a "(\\d+)" route that the specificity order ranks alongside the ":id"
// routes. Every hit on the compiled fast path decides, at creation, whether
// this route can outrank it: no ":id" or static winner can be outranked by
// it, and only a "/*" miss under "/api/v1/invoices/" is a legitimate
// candidate, so std::regex runs for at most one URL of the stream instead
// of every one.
static const std::vector<std::string>& route_table_with_regexp() {
  static const std::vector<std::string> routes = [] {
    std::vector<std::string> r = route_table();
    r.push_back("/api/v1/invoices/(\\d+)/pdf");
    return r;
  }();
  return routes;
}

// A deterministic stream of request pathnames: instantiated hits over the
// route table plus a share of misses (the final "/*" catches them; a match
// is still found, exercising the worst backtracking path of both sides).
// Both benchmarks iterate this same stream, so the comparison stays honest.
// The stream is kept short (32 URLs) so one iteration of the sequential
// url_pattern::exec loop stays well under CodSpeed's per-iteration budget;
// the ns/url counters normalize the stream length away.
static std::vector<std::string> make_stream(bool static_only, bool param_only) {
  std::vector<std::string> u;
  uint64_t x = 0x14C0FFEEull;  // splitmix64
  auto next = [&x]() {
    uint64_t z = (x += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  };
  auto token = [&next]() {
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string t;
    size_t len = 3 + next() % 8;
    for (size_t j = 0; j < len; j++) {
      t += alphabet[next() % (sizeof(alphabet) - 1)];
    }
    return t;
  };
  const auto& routes = route_table();
  while (u.size() < 32) {
    const std::string& pattern = routes[next() % routes.size()];
    const bool has_group = pattern.find(':') != std::string::npos ||
                           pattern.find('*') != std::string::npos;
    if ((static_only && has_group) ||
        (param_only && pattern.find(':') == std::string::npos)) {
      continue;
    }
    std::string url;
    size_t pos = 0;
    while (pos < pattern.size()) {
      if (pattern[pos] == ':') {
        while (pos < pattern.size() && pattern[pos] != '/') {
          pos++;
        }
        url += token();
      } else if (pattern[pos] == '*') {
        pos++;
        url += token();
        url += '/';
        url += token();
      } else {
        url += pattern[pos++];
      }
    }
    if (!static_only && !param_only && next() % 5 == 0) {
      url += "/zz";  // ~20% misses-by-mutation
    }
    u.push_back(std::move(url));
  }
  return u;
}

static const std::vector<std::string>& url_stream() {
  static const std::vector<std::string> urls = make_stream(false, false);
  return urls;
}

static const std::vector<std::string>& static_stream() {
  static const std::vector<std::string> urls = make_stream(true, false);
  return urls;
}

static const std::vector<std::string>& param_stream() {
  static const std::vector<std::string> urls = make_stream(false, true);
  return urls;
}

static std::vector<ada::url_pattern<regex_provider>>& sequential_patterns() {
  static std::vector<ada::url_pattern<regex_provider>> patterns = [] {
    std::vector<ada::url_pattern<regex_provider>> p;
    for (const std::string& route : route_table()) {
      auto pattern = ada::parse_url_pattern<regex_provider>(
          ada::url_pattern_init{.pathname = route});
      if (pattern) {
        p.push_back(std::move(*pattern));
      }
    }
    return p;
  }();
  return patterns;
}

static list_type compile_list(const std::vector<std::string>& routes) {
  std::vector<std::string_view> views(routes.begin(), routes.end());
  auto result = ada::parse_url_pattern_list<regex_provider>(views);
  if (!result) {
    std::cerr << "parse_url_pattern_list failed" << std::endl;
    std::abort();
  }
  return std::move(*result);
}

static const list_type& compiled_list() {
  static const list_type list = compile_list(route_table());
  return list;
}

static const list_type& compiled_list_with_regexp() {
  static const list_type list = compile_list(route_table_with_regexp());
  return list;
}

// First match of the sequential url_pattern::exec loop -- the routing loop
// the URLPattern API offers today.
static int32_t sequential_route(std::string_view url) {
  auto& patterns = sequential_patterns();
  const ada::url_pattern_input input(
      ada::url_pattern_init{.pathname = std::string(url)});
  for (size_t i = 0; i < patterns.size(); i++) {
    auto result = patterns[i].exec(input);
    if (result && result->has_value()) {
      return static_cast<int32_t>(i);
    }
  }
  return -1;
}

static void add_counters(benchmark::State& state, size_t n_urls) {
  state.counters["ns/url"] = benchmark::Counter(
      static_cast<double>(state.iterations()) * static_cast<double>(n_urls),
      benchmark::Counter::kIsRate | benchmark::Counter::kInvert);
  state.counters["urls/s"] = benchmark::Counter(
      static_cast<double>(state.iterations()) * static_cast<double>(n_urls),
      benchmark::Counter::kIsRate);
}

static void BasicBench_SequentialURLPatternExec(benchmark::State& state) {
  const auto& urls = url_stream();
  volatile int64_t sum = 0;
  for (auto _ : state) {
    for (const std::string& url : urls) {
      sum += sequential_route(url);
    }
  }
  (void)sum;
  add_counters(state, urls.size());
}
BENCHMARK(BasicBench_SequentialURLPatternExec);

static void list_bench(benchmark::State& state, const list_type& list,
                       const std::vector<std::string>& urls) {
  volatile int64_t sum = 0;
  for (auto _ : state) {
    for (const std::string& url : urls) {
      sum += list.match(url).route_index;
    }
  }
  (void)sum;
  add_counters(state, urls.size());
}

static void BasicBench_URLPatternListMatch(benchmark::State& state) {
  list_bench(state, compiled_list(), url_stream());
}
BENCHMARK(BasicBench_URLPatternListMatch);

// Static-route hits only and ":param"-route hits only, to see each path.
static void BasicBench_URLPatternListMatch_StaticHits(benchmark::State& state) {
  list_bench(state, compiled_list(), static_stream());
}
BENCHMARK(BasicBench_URLPatternListMatch_StaticHits);

static void BasicBench_URLPatternListMatch_ParamHits(benchmark::State& state) {
  list_bench(state, compiled_list(), param_stream());
}
BENCHMARK(BasicBench_URLPatternListMatch_ParamHits);

// The same stream over the table with one "(\\d+)" regexp route present:
// the cost of a regexp route in the table must not be a std::regex
// execution per request.
static void BasicBench_URLPatternListMatch_WithRegexpRoute(
    benchmark::State& state) {
  list_bench(state, compiled_list_with_regexp(), url_stream());
}
BENCHMARK(BasicBench_URLPatternListMatch_WithRegexpRoute);

int main(int argc, char** argv) {
  // Cross-check: the route table is ordered static -> param -> wildcard, so
  // insertion-order first match and specificity order must agree; any
  // disagreement would invalidate the comparison. The regexp variant must
  // answer the same stream identically (its extra route matches nothing in
  // it).
  size_t disagreements = 0;
  const auto& list = compiled_list();
  const auto& with_regexp = compiled_list_with_regexp();
  for (const std::string& url : url_stream()) {
    const int32_t expected = sequential_route(url);
    if (expected != list.match(url).route_index ||
        expected != with_regexp.match(url).route_index) {
      disagreements++;
    }
  }
  benchmark::AddCustomContext("routes", std::to_string(route_table().size()));
  benchmark::AddCustomContext("urls in stream",
                              std::to_string(url_stream().size()));
  benchmark::AddCustomContext("sequential-vs-list disagreements",
                              std::to_string(disagreements));
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
}
