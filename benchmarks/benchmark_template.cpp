#if BOOST_ENABLED
#include <boost/url/src.hpp>
using namespace boost::urls;
/** Boost URL does some lazy parsing. **/
static void BasicBench_BoostURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t numbers_of_parameters = 0;
  event_aggregate aggregate{};
  for (auto _ : state) {
    collector.start();
    for(std::string& url_string : url_examples) {
        url_view uv(url_string);
        numbers_of_parameters += uv.params().size();
        // TODO: use the content.
    }
    event_count allocate_count = collector.end();
    aggregate << allocate_count;
  }
  if(collector.has_events()) {
    
    event_aggregate aggregate{};
    for(size_t i = 0 ; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for(std::string& url_string : url_examples) {
        url_view uv(url_string);
        numbers_of_parameters += uv.params().size();
        // TODO: use the content.
      }
      std::atomic_thread_fence(std::memory_order_release);  
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }  
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.total.instructions() / aggregate.total.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["GHz"] = aggregate.total.cycles() / aggregate.total.elapsed_ns();
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
#endif


#if CURL_ENABLED
#include <curl/curl.h>

static void BasicBench_CURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid{true};
  CURLU *url = curl_url();
  for (auto _ : state) {
    collector.start();
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
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.total.instructions() / aggregate.total.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["GHz"] = aggregate.total.cycles() / aggregate.total.elapsed_ns();
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
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.total.instructions() / aggregate.total.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["GHz"] = aggregate.total.cycles() / aggregate.total.elapsed_ns();
  }
   uriFreeUriMembersA(&uri);

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
BENCHMARK(BasicBench_uriparser);


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
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.total.instructions() / aggregate.total.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["GHz"] = aggregate.total.cycles() / aggregate.total.elapsed_ns();
  }

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
BENCHMARK(BasicBench_urlparser);

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
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.total.instructions() / aggregate.total.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["GHz"] = aggregate.total.cycles() / aggregate.total.elapsed_ns();
  }

  if(!is_valid) { std::cout << "http_parser: invalid? " << std::endl; }
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
BENCHMARK(BasicBench_http_parser);

static void BasicBench_AdaURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid = true;

  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
      auto url = ada::parser::parse_url(url_string, std::nullopt);
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
        is_valid &= url.is_valid;
      }
      std::atomic_thread_fence(std::memory_order_release); 
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["instructions/url"] = aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] = aggregate.total.instructions() / aggregate.total.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / url_examples_bytes;
    state.counters["GHz"] = aggregate.total.cycles() / aggregate.total.elapsed_ns();
  }
  if(!is_valid) { std::cout << "ada: invalid? " << std::endl; }
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
BENCHMARK(BasicBench_AdaURL);



int main(int argc, char **argv) {
#if CURL_ENABLED
    // the curl dependency will depend on the system.
    benchmark::AddCustomContext("curl version ", LIBCURL_VERSION);
#else
    benchmark::AddCustomContext("curl ", "OMITTED");
#endif
#if !BOOST_ENABLED
    benchmark::AddCustomContext("boost ", "OMITTED");
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
    if(collector.has_events()) {
      benchmark::AddCustomContext("performance counters", "Enabled");
      if(url_examples_bytes < 1000) {
        benchmark::AddCustomContext("Warning", "URL volume too small for accurate counters");
      }
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
}
