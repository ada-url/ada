#include <iostream>
#include <boost/url/src.hpp>
#include <benchmark/benchmark.h>
using namespace boost::urls;

static void BasicBench_BoostURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t numbers_of_parameters = 0;
  for (auto _ : state) {
    // This code gets timed
    // silly code!!!
    url_view uv( "https://www.example.com/path/to/file.txt?id=1001&name=John%20Doe&results=full" );
    numbers_of_parameters = uv.params().size();
  }
  (void)numbers_of_parameters;
}
BENCHMARK(BasicBench_BoostURL);
BENCHMARK_MAIN();
