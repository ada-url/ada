#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>

#include "ada.h"
#include "performancecounters/event_counter.h"
event_collector collector;

bool file_exists(const char *filename) {
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

std::vector<std::string> split_string(const std::string &str) {
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
  std::string href{};
  ada::url_components components{};
  event_aggregate counters{};
  bool is_valid = true;
  bool has_port = false;
  bool has_credentials = false;
  bool has_fragment = false;
  bool has_search = false;
};

size_t count_ascii_bytes(const std::string &s) {
  size_t counter = 0;
  for (uint8_t c : s) {
    if (c < 128) {
      counter++;
    }
  }
  return counter;
}

template <class result_type = ada::url_aggregator>
std::vector<stat_numbers> collect_values(
    const std::vector<std::string> &url_examples, size_t trials) {
  std::vector<stat_numbers> numbers(url_examples.size());
  for (size_t i = 0; i < url_examples.size(); i++) {
    numbers[i].url_string = url_examples[i];
    ada::result<result_type> url = ada::parse<result_type>(url_examples[i]);
    if (url) {
      numbers[i].is_valid = true;
      numbers[i].href = url->get_href();
      numbers[i].components = url->get_components();
      numbers[i].has_port = url->has_port();
      numbers[i].has_credentials = url->has_credentials();
      numbers[i].has_fragment = url->has_hash();
      numbers[i].has_search = url->has_search();
    } else {
      numbers[i].is_valid = false;
    }
  }
  volatile size_t href_size = 0;
  for (size_t i = 0; i < trials; i++) {
    for (stat_numbers &n : numbers) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      ada::result<result_type> url = ada::parse<result_type>(n.url_string);
      if (url) {
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
const char *default_file = ADA_URL_FILE;
#else
const char *default_file = nullptr;
#endif

std::vector<std::string> init_data(const char *input = default_file) {
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

void print(const stat_numbers &n) {
  std::cout << std::setw(15) << n.url_string.size() << ",";
  std::cout << std::setw(15) << n.counters.best.cycles() << "," << std::setw(15)
            << size_t(n.counters.cycles()) << ",";
  std::cout << std::setw(15) << n.counters.best.instructions() << ","
            << std::setw(15) << n.counters.instructions() << ",";
  std::cout << std::setw(15) << n.is_valid << ",";

  // hash size

  std::cout << std::setw(15) << n.href.size() << ",";
  size_t end = n.href.size();
  if (n.components.hash_start != ada::url_components::omitted) {
    std::cout << std::setw(15) << (end - n.components.hash_start) << ",";
    end = n.components.hash_start;
  } else {
    std::cout << std::setw(15) << 0 << ",";
  }
  // search size
  if (n.components.search_start != ada::url_components::omitted) {
    std::cout << std::setw(15) << (end - n.components.search_start) << ",";
    end = n.components.search_start;
  } else {
    std::cout << std::setw(15) << 0 << ",";
  }
  // path size
  std::cout << std::setw(15) << (end - n.components.pathname_start) << ",";
  end = n.components.pathname_start;
  // port size
  std::cout << std::setw(15) << (end - n.components.host_end) << ",";
  end = n.components.host_end;
  // host size
  std::cout << std::setw(15) << (end - n.components.host_start) << ",";
  end = n.components.host_start;
  // user/pass size
  std::cout << std::setw(15) << (end - n.components.protocol_end) << ",";
  end = n.components.protocol_end;
  // protocol type
  ada::result<ada::url_aggregator> url =
      ada::parse<ada::url_aggregator>(n.url_string);
  if (url) {
    std::cout << std::setw(15) << int(url->type);
  } else {
    std::cout << std::setw(15) << -1;
  }
  std::cout << ",";
  std::cout << std::setw(15) << n.has_port << ",";
  std::cout << std::setw(15) << n.has_credentials << ",";
  std::cout << std::setw(15) << n.has_fragment << ",";
  std::cout << std::setw(15) << n.has_search << ",";
  std::cout << std::setw(15)
            << (n.url_string.size() - count_ascii_bytes(n.url_string)) << ",";
  std::cout << std::setw(15) << (n.href.size() - count_ascii_bytes(n.href))
            << ",";
  std::cout << std::setw(15)
            << (count_ascii_bytes(n.url_string) == n.url_string.size()) << ",";
  std::cout << std::setw(15) << (n.href == n.url_string);
}
void print(const std::vector<stat_numbers> numbers) {
  std::cout << std::setw(15) << "input_size"
            << ",";
  std::cout << std::setw(15) << "best_cycles"
            << ",";
  std::cout << std::setw(15) << "mean_cycles"
            << ",";
  std::cout << std::setw(15) << "best_instr"
            << ",";
  std::cout << std::setw(15) << "mean_instr"
            << ",";
  std::cout << std::setw(15) << "is_valid"
            << ",";
  std::cout << std::setw(15) << "href_size"
            << ",";
  std::cout << std::setw(15) << "hash_size"
            << ",";
  std::cout << std::setw(15) << "search_size"
            << ",";
  std::cout << std::setw(15) << "path_size"
            << ",";
  std::cout << std::setw(15) << "port_size"
            << ",";
  std::cout << std::setw(15) << "host_size"
            << ",";
  std::cout << std::setw(15) << "credential_size"
            << ",";
  std::cout << std::setw(15) << "protocol_type"
            << ",";
  std::cout << std::setw(15) << "has_port"
            << ",";
  std::cout << std::setw(15) << "has_authority"
            << ",";
  std::cout << std::setw(15) << "has_fragment"
            << ",";
  std::cout << std::setw(15) << "has_search"
            << ",";
  std::cout << std::setw(15) << "non_ascii_bytes"
            << ",";
  std::cout << std::setw(15) << "href_non_ascii_bytes"
            << ",";
  std::cout << std::setw(15) << "is_ascii"
            << ",";
  std::cout << std::setw(15) << "input_is_href";

  std::cout << std::endl;

  for (const stat_numbers &n : numbers) {
    print(n);
    std::cout << std::endl;
  }
}

int main(int argc, char **argv) {
  std::vector<std::string> input_urls;
  if (argc == 1) {
    input_urls = init_data();
  } else {
    input_urls = init_data(argv[1]);
  }
  if (input_urls.empty()) {
    std::cout << "pass the path to a file containing a list of URL (one per "
                 "line) as a parameter."
              << std::endl;
    return EXIT_FAILURE;
  }
  if (!collector.has_events()) {
    std::cout << "We require access to performance counters. (Try sudo.)"
              << std::endl;
    return EXIT_FAILURE;
  }
  std::string empty;
  // We always start with a null URL for calibration.
  input_urls.insert(input_urls.begin(), empty);
  bool use_ada_url = (getenv("USE_URL") != nullptr);
  size_t trials = 100;
  std::cout << "# trials " << trials << std::endl;
  if (use_ada_url) {
    std::cout << "# ada::url" << std::endl;
    print(collect_values<ada::url>(input_urls, trials));
  } else {
    std::cout << "# ada::url_aggregator" << std::endl;
    print(collect_values<ada::url_aggregator>(input_urls, trials));
  }

  return EXIT_SUCCESS;
}
