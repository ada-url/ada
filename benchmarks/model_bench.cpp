#include <iostream>
#include <memory>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <filesystem>


#include "ada.h"
#include "performancecounters/event_counter.h"
event_collector collector;

bool file_exists(const char* filename) {
  namespace fs = std::filesystem;
  std::filesystem::path f{filename};
  if (std::filesystem::exists(filename)) {
    return true;
  } else {
    std::cout << "  file missing: " << filename << std::endl;
    return false;
  }
}

std::string read_file(std::string filename) {
  constexpr auto read_size = std::size_t(4096);
  auto stream = std::ifstream(filename.c_str());
  stream.exceptions(std::ios_base::badbit);
  auto out = std::string();
  auto buf = std::string(read_size, '\0');
  while (stream.read(&buf[0], read_size)) {
    out.append(buf, 0, size_t(stream.gcount()));
  }
  out.append(buf, 0, size_t(stream.gcount()));
  return out;
}

std::vector<std::string> split_string(const std::string& str) {
  auto result = std::vector<std::string>{};
  auto ss = std::stringstream{str};
  for (std::string line; std::getline(ss, line, '\n');) {
    std::string_view view = line;
    // Some parsers like boost/url will refuse to parse a URL with trailing
    // whitespace.
    while (!view.empty() && std::isspace(view.back())) {
      view.remove_suffix(1);
    }
    while (!view.empty() && std::isspace(view.front())) {
      view.remove_prefix(1);
    }
    if (!view.empty()) {
      result.emplace_back(view);
    }
  }
  return result;
}



struct stat_numbers {
  std::string url_string{};
  ada::url_components components{};
  event_aggregate counters{};
  bool is_valid = true;
};

template <class result_type = ada::url_aggregator>
std::vector<stat_numbers> collect_values(const std::vector<std::string>& url_examples, size_t trials) {
    std::vector<stat_numbers> numbers(url_examples.size());
    for(size_t i = 0; i < url_examples.size(); i++) {
        numbers[i].url_string = url_examples[i];
        ada::result<result_type> url = ada::parse<result_type>(url_examples[i]);
        if(url) {
            numbers[i].is_valid = true;
            numbers[i].components = url->get_components();
        } else {
            numbers[i].is_valid = false;
        }
    }
    volatile size_t href_size = 0;
    for(size_t i = 0; i < trials; i++) {
        for (stat_numbers& n : numbers) {
            std::atomic_thread_fence(std::memory_order_acquire);
            collector.start();
            ada::result<result_type> url = ada::parse<result_type>(n.url_string);
            if(url) {
              href_size += url->get_href().size();
            }
            std::atomic_thread_fence(std::memory_order_release);
            event_count allocate_count = collector.end();
            n.counters << allocate_count;
        }
    }
    return numbers;
}



#ifdef ADA_URL_FILE
const char* default_file = ADA_URL_FILE;
#else
const char* default_file = nullptr;
#endif

std::vector<std::string> init_data(const char* input = default_file) {
  std::vector<std::string> input_urls;
  if (input == nullptr) {
    return input_urls;
  }

  if (!file_exists(input)) {
    std::cout << "File not found !" << input << std::endl;
    return input_urls;
  } else {
    std::cout << "# Loading " << input << std::endl;
    input_urls = split_string(read_file(input));
  }
  return input_urls;
}

void print(const stat_numbers & n) {
  std::cout << n.url_string.size() << "\t\t";
  std::cout <<  n.counters.best.elapsed_ns() << "\t\t" << n.counters.elapsed_ns() << "\t\t";
  std::cout <<  n.counters.best.cycles() << "\t\t" << n.counters.cycles() << "\t\t";
  std::cout <<  n.counters.best.instructions() << "\t\t" << n.counters.instructions() << "\t\t";       
}
void print(const std::vector<stat_numbers> numbers) {
  std::cout << "input_size\t";
  std::cout <<   "best_elapsed_ns\tmean_elapsed_ns\t";
  std::cout <<  "best_cycles\tmean_cycles\t";
  std::cout <<  "best_instr\tmean_instr\t";
                 std::cout << std::endl;


    for(const stat_numbers & n : numbers) {
        print(n);
        std::cout << std::endl;
    }
}

int main(int argc, char **argv) {
  std::vector<std::string> input_urls;
  if(argc == 1) {
    input_urls = init_data();
  } else {
    input_urls = init_data(argv[1]);
  }
  if (input_urls.empty()) {
    std::cout
        << "pass the path to a file containing a list of URL (one per line) as a parameter."
        << std::endl;
    return EXIT_FAILURE;
  }
  if (!collector.has_events()) {
    std::cout << "We require access to performance counters. (Try sudo.)" << std::endl;
    return EXIT_FAILURE;
  }
  std::string empty;
  input_urls.insert(input_urls.begin(), empty);
  input_urls.insert(input_urls.begin(), empty);
  input_urls.insert(input_urls.begin(), empty);
  input_urls.insert(input_urls.begin(), empty);

  print(collect_values<ada::url_aggregator>(input_urls, 30));
  return EXIT_SUCCESS;
}