/**
 * The task for the parsers is to fill in this struct.
 */
struct standard_url {
  int port;
  std::string scheme;
  std::string username;
  std::string password;
  std::string host;
  std::string query;
  std::string fragment;
  std::string path;
  std::string href;
};

// container where the parsers write their results.
std::vector<standard_url> url_container;


inline standard_url to_standard_url(ada::url* url) {
  // Important: below we *move* the strings, we do not copy them.
  standard_url u;
  u.port = url->port.has_value() ? url->port.value() : -1;
  u.scheme = url->get_scheme();
  u.username = std::move(url->username);
  u.password = std::move(url->password);
  if(url->host.has_value()) { u.host = std::move(*url->host); }
  u.path = std::move(url->path);
  if(url->fragment.has_value()) { u.fragment = std::move(*url->fragment); }
  if(url->query.has_value()) { u.query = std::move(*url->query); }
  return u;
}


inline standard_url to_standard_url_with_copy(ada::url* url) {
  standard_url u;
  u.port = url->port.has_value() ? url->port.value() : -1;
  u.scheme = url->get_scheme();
  u.username = url->username;
  u.password = url->password;
  if(url->host.has_value()) { u.host = *url->host; }
  u.path = url->path;
  if(url->fragment.has_value()) { u.fragment = *url->fragment; }
  if(url->query.has_value()) { u.query = *url->query; }
  return u;
}

template <bool with_copy = false>
static void BasicBench_AdaURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t numbers_of_parameters = 0;
  url_container.reserve(std::size(url_examples));

  for (auto _ : state) {
    url_container.clear();
    for(std::string& url_string : url_examples) {
      auto url = ada::parse(url_string);
      if(url) {
        if(with_copy) {
          url_container.emplace_back(to_standard_url_with_copy(&*url));
        } else {
          url_container.emplace_back(to_standard_url(&*url));
        }
      }
    }
    numbers_of_parameters += url_container.size();
  }
  if(collector.has_events()) {

    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      url_container.clear();
      for(std::string& url_string : url_examples) {
        auto url = ada::parse(url_string);
        if(url) {
          if(with_copy) {
            url_container.emplace_back(to_standard_url_with_copy(&*url));
          } else {
            url_container.emplace_back(to_standard_url(&*url));
          }
        }
      }
      numbers_of_parameters += url_container.size();
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["cycles/url"] = aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] = aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] = aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] = aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }
  (void)numbers_of_parameters;
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
          url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate);
}

BENCHMARK(BasicBench_AdaURL);




#if ADA_url_whatwg_ENABLED


inline standard_url to_standard_url(whatwg::url* url) {
  // It might be possible to do better performance-wise.
  standard_url u;
  u.port = url->port_int();
  u.scheme = url->protocol();
  u.username = url->username();
  u.password = url->password();
  u.host = url->host();
  u.path = url->pathname();
  u.fragment = url->hash();
  u.query = url->search();
  return u;
}

static void BasicBench_whatwg(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t numbers_of_parameters = 0;
  url_container.reserve(std::size(url_examples));
  for (auto _ : state) {
    url_container.clear();
    for(std::string& url_string : url_examples) {
        whatwg::url url;
        if (whatwg::success(url.parse(url_string, nullptr))) {
          url_container.emplace_back(to_standard_url(&url));
        }
    }
    numbers_of_parameters += url_container.size();
  }
  if(collector.has_events()) {
    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      url_container.clear();
      for(std::string& url_string : url_examples) {
        whatwg::url url;
        if (whatwg::success(url.parse(url_string, nullptr))) {
          url_container.emplace_back(to_standard_url(&url));
        }
      }
      numbers_of_parameters += url_container.size();
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["cycles/url"] = aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] = aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] = aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] = aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }
  (void)numbers_of_parameters;
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
	        std::size(url_examples),
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
          url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
	        std::size(url_examples),
          benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_whatwg);
#endif // ADA_url_whatwg_ENABLED

#if ADA_CURL_ENABLED
#include <curl/curl.h>


inline standard_url to_standard_url(CURLU *url) {
  standard_url u;
  CURLUcode rc;
  char *buffer;
  rc = curl_url_get(url, CURLUPART_SCHEME, &buffer, 0);
  if(!rc) {
      u.scheme = buffer;
      curl_free(buffer);
  }
  rc = curl_url_get(url, CURLUPART_HOST, &buffer, 0);
  if(!rc) {
      u.host = buffer;
      curl_free(buffer);
  }
  rc = curl_url_get(url, CURLUPART_PATH, &buffer, 0);
  if(!rc) {
      u.path = buffer;
      curl_free(buffer);
  }
  rc = curl_url_get(url, CURLUPART_QUERY, &buffer, 0);
  if(!rc) {
      u.query = buffer;
      curl_free(buffer);
  }
  rc = curl_url_get(url, CURLUPART_FRAGMENT, &buffer, 0);
  if(!rc) {
      u.fragment = buffer;
      curl_free(buffer);
  }
  rc = curl_url_get(url, CURLUPART_USER, &buffer, 0);
  if(!rc) {
      u.username = buffer;
      curl_free(buffer);
  }
  rc = curl_url_get(url, CURLUPART_PORT, &buffer, 0);
  if(!rc) {
      u.port = atoi(buffer);
      curl_free(buffer);
  } else {
    u.port = -1;
  }
  return u;
}

// curl follows RFC3986+
static void BasicBench_CURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t numbers_of_parameters = 0;
  url_container.reserve(std::size(url_examples));
  CURLU *url = curl_url();
  for (auto _ : state) {
    url_container.clear();
    for(std::string& url_string : url_examples) {
      CURLUcode rc = curl_url_set(url, CURLUPART_URL, url_string.c_str(), 0);
      if(rc) { url_container.emplace_back(to_standard_url(url)); }
    }
    numbers_of_parameters += url_container.size();
  }
  if(collector.has_events()) {

    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      url_container.clear();
      for(std::string& url_string : url_examples) {
        CURLUcode rc = curl_url_set(url, CURLUPART_URL, url_string.c_str(), 0);
        if(rc) { url_container.emplace_back(to_standard_url(url)); }
      }
      numbers_of_parameters += url_container.size();
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["cycles/url"] = aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] = aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] = aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] = aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }
  curl_free(url);
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
	        std::size(url_examples),
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
          url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
	        std::size(url_examples),
          benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_CURL);
#endif


#if ADA_BOOST_ENABLED
#include <boost/url/src.hpp>
using namespace boost::urls;


inline standard_url to_standard_url(boost::urls::url_view* url) {
  standard_url u;
  u.port = url->port_number();
  u.scheme = url->scheme();
  u.username = url->encoded_user();
  u.password = url->encoded_password();
  u.host = url->encoded_host();   
  u.path = url->encoded_path();
  if (u.path.empty()) {
    u.path = "/";
  }
  u.fragment = url->encoded_fragment();
  u.query = url->encoded_query();
  return u;
}

// Boost URL follows RFC3986
static void BasicBench_BoostURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t numbers_of_parameters = 0;
  url_container.reserve(std::size(url_examples));
  for (auto _ : state) {
    url_container.clear();
    for(std::string& url_string : url_examples) {
        result<url_view> uv = parse_uri(url_string);
        if(uv.has_value()) { url_container.emplace_back(to_standard_url(&uv.value())); }
    }
    numbers_of_parameters += url_container.size();
  }
  if(collector.has_events()) {
    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      url_container.clear();
      for(std::string& url_string : url_examples) {
        result<url_view> uv = parse_uri(url_string);
        if(uv.has_value()) { url_container.emplace_back(to_standard_url(&uv.value())); }
      }
      numbers_of_parameters += url_container.size();
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["cycles/url"] = aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] = aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] = aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] = aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }
  (void)numbers_of_parameters;
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
	        std::size(url_examples),
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
          url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
	        std::size(url_examples),
          benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_BoostURL);
#endif // ADA_BOOST_ENABLED

#if ADA_VARIOUS_COMPETITION_ENABLED
static void BasicBench_uriparser(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid = true;
  const char * errorPos;
  UriUriA uri;
  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
        is_valid &= (uriParseSingleUriA(&uri, url_string.c_str(), &errorPos) == URI_SUCCESS);
    }
  }
  if(!is_valid) { std::cout << "uri-parser: invalid? " << std::endl; }
  if(collector.has_events()) {

    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for(std::string& url_string : url_examples) {
        is_valid &= (uriParseSingleUriA(&uri, url_string.c_str(), &errorPos) == URI_SUCCESS);
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["cycles/url"] = aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] = aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] = aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] = aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }
   uriFreeUriMembersA(&uri);

  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
          url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_uriparser);
#endif // ADA_VARIOUS_COMPETITION_ENABLED

#if ADA_VARIOUS_COMPETITION_ENABLED
static void BasicBench_urlparser(benchmark::State& state) {
  // volatile to prevent optimizations.
  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
      std::unique_ptr<EdUrlParser> url(EdUrlParser::parseUrl(url_string));
    }
  }
  if(collector.has_events()) {
    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for(std::string& url_string : url_examples) {
        std::unique_ptr<EdUrlParser> url(EdUrlParser::parseUrl(url_string));
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["cycles/url"] = aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] = aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] = aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] = aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }

  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
          url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_urlparser);
#endif // ADA_VARIOUS_COMPETITION_ENABLED

#if ADA_VARIOUS_COMPETITION_ENABLED
static void BasicBench_http_parser(benchmark::State& state) {
  volatile bool is_valid{true};
  struct http_parser_url u;
  http_parser_url_init(&u);
  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
      is_valid &= !http_parser_parse_url(url_string.data(), url_string.size(), 0, &u);
    }
  }
  if(collector.has_events()) {

    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for(std::string& url_string : url_examples) {
        is_valid &= !http_parser_parse_url(url_string.data(), url_string.size(), 0, &u);
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["cycles/url"] = aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] = aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] = aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] = aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }

  if(!is_valid) { std::cout << "http_parser: invalid? " << std::endl; }
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
          url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_http_parser);
#endif // ADA_VARIOUS_COMPETITION_ENABLED

int main(int argc, char **argv) {
    benchmark::AddCustomContext("ada spec", "Ada follows whatwg/url");
#if defined(ADA_RUST_VERSION)
    benchmark::AddCustomContext("rust version ", ADA_RUST_VERSION);
#endif
#if ADA_CURL_ENABLED
    // the curl dependency will depend on the system.
    benchmark::AddCustomContext("curl version ", LIBCURL_VERSION);
    benchmark::AddCustomContext("curl spec", "Curl follows RFC3986, not whatwg/url");
#else
    benchmark::AddCustomContext("curl ", "OMITTED");
#endif
#if ADA_BOOST_ENABLED
    benchmark::AddCustomContext("boost-url spec", "Boost URL follows RFC3986, not whatwg/url");
#endif
#if (__APPLE__ &&  __aarch64__) || defined(__linux__)
    if(!collector.has_events()) {
      benchmark::AddCustomContext("performance counters", "No privileged access (sudo may help).");
    }
#else
    if(!collector.has_events()) {
      benchmark::AddCustomContext("performance counters", "Unsupported system.");
    }
#endif
    benchmark::AddCustomContext("input bytes", std::to_string(size_t(url_examples_bytes)));
    benchmark::AddCustomContext("number of URLs", std::to_string(std::size(url_examples)));
    benchmark::AddCustomContext("bytes/URL", std::to_string(url_examples_bytes/std::size(url_examples)));
#if ADA_VARIOUS_COMPETITION_ENABLED
    benchmark::AddCustomContext("WARNING", "BasicBench_urlparser and BasicBench_uriparser do not use a normalized task.");
#endif
    if(collector.has_events()) {
      benchmark::AddCustomContext("performance counters", "Enabled");
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
}

#if defined(ADA_RUST_VERSION)
#include "competitors/servo-url/servo_url.h"

// Emilio from Mozilla recommended that using an opaque-pointer will improve the performance
// of this benchmark. It has indeed improved but with the cost of validating the output.
// Reference: https://twitter.com/ecbos_/status/1627494441656238082?s=61&t=vCdcfSGWHH056CBdklWfCg
static void BasicBench_ServoUrl(benchmark::State& state) {
  // Other benchmarks copy the 'standard url' to a structure.
  // We try to mimick the effect.
  std::vector<servo_url::Url*> rust_url_container;
  rust_url_container.reserve(std::size(url_examples));

  for (auto _ : state) {
    while(!rust_url_container.empty()) {
      servo_url::free_url(rust_url_container.back());
      rust_url_container.pop_back();
    }
    for(std::string& url_string : url_examples) {
      // benchmark::DoNotOptimize is unnecessary and potentially misleading.
      servo_url::Url * url = servo_url::parse_url(url_string.c_str(), url_string.length());
      rust_url_container.push_back(url);
    }
  }
  if(collector.has_events()) {
    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      // mimicks a clear()
      while(!rust_url_container.empty()) {
        servo_url::free_url(rust_url_container.back());
        rust_url_container.pop_back();
      }
      for(std::string& url_string : url_examples) {
        servo_url::Url * url = servo_url::parse_url(url_string.c_str(), url_string.length());
        rust_url_container.push_back(url);
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    // let us not leak memory:
    while(!rust_url_container.empty()) {
      servo_url::free_url(rust_url_container.back());
      rust_url_container.pop_back();
    }
    state.counters["cycles/url"] = aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] = aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] = aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] = aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }

  state.counters["time/byte"] = benchmark::Counter(
      url_examples_bytes,
      benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
      double(std::size(url_examples)),
      benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
      double(std::size(url_examples)),
      benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_ServoUrl);
#endif // ADA_RUST
