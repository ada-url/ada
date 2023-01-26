

static void BasicBench_AdaURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid = true;
  volatile size_t numbers_of_parameters = 0;

  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
      auto url = ada::parser::parse_url(url_string, std::nullopt);
      numbers_of_parameters += url.path.size()
       + (url.query.has_value() ? url.query->size() : 0) + url.get_scheme().size() + url.host->size();
      is_valid &= url.is_valid;
    }
  }
  if(collector.has_events()) {

    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for(std::string& url_string : url_examples) {
        auto url = ada::parser::parse_url(url_string, std::nullopt);
        numbers_of_parameters += url.path.size()
         + (url.query.has_value() ? url.query->size() : 0) + url.get_scheme().size()
         + (url.host.has_value() ? url.host->size() : 0);
        is_valid &= url.is_valid;
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
  if(!is_valid) { std::cout << "ada: invalid? " << std::endl; }
  (void)numbers_of_parameters;
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["url/s"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_AdaURL);



#if ADA_CURL_ENABLED
#include <curl/curl.h>

static void BasicBench_CURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid{true};
  CURLU *url = curl_url();
  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
      CURLUcode rc = curl_url_set(url, CURLUPART_URL, url_string.c_str(), 0);
      if(rc) { is_valid = false; }
    }
  }
  if(collector.has_events()) {

    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for(std::string& url_string : url_examples) {
        CURLUcode rc = curl_url_set(url, CURLUPART_URL, url_string.c_str(), 0);
        if(rc) { is_valid = false; }
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
  curl_url_cleanup(url);
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
	        std::size(url_examples),
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["url/s"] = benchmark::Counter(
	        std::size(url_examples),
          benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_CURL);
#endif


#if ADA_BOOST_ENABLED
#include <boost/url/src.hpp>
using namespace boost::urls;
static void BasicBench_BoostURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t numbers_of_parameters = 0;
  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
        url_view uv(url_string);
        numbers_of_parameters += uv.params().size()
          + uv.encoded_path().size() + uv.encoded_query().size()
          + uv.encoded_host_name().size() + uv.scheme().size();
    }
  }
  if(collector.has_events()) {
    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for(std::string& url_string : url_examples) {
        url_view uv(url_string);
        numbers_of_parameters += uv.params().size()
          + uv.encoded_path().size() + uv.encoded_query().size()
          + uv.encoded_host_name().size() + uv.scheme().size();
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
  (void)numbers_of_parameters;
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
	        std::size(url_examples),
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
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
  state.counters["url/s"] = benchmark::Counter(
	        double(std::size(url_examples)),
          benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_http_parser);
#endif // ADA_VARIOUS_COMPETITION_ENABLED

int main(int argc, char **argv) {
#if ADA_CURL_ENABLED
    // the curl dependency will depend on the system.
    benchmark::AddCustomContext("curl version ", LIBCURL_VERSION);
#else
    benchmark::AddCustomContext("curl ", "OMITTED");
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

    if(collector.has_events()) {
      benchmark::AddCustomContext("performance counters", "Enabled");
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
}
