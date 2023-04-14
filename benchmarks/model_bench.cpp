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
  std::string href{};
  ada::url_components components{};
  event_aggregate counters{};
  bool is_valid = true;
  bool has_port = false;
  bool has_authority = false;
  bool has_fragment = false;
  bool has_search = false;
};

size_t count_ascii_bytes(const std::string& s) {
  size_t counter = 0;
  for(uint8_t c : s) {
    if (c < 128) {
      counter++;
    }
  }
  return counter;
}

template <class result_type = ada::url_aggregator>
std::vector<stat_numbers> collect_values(
    const std::vector<std::string>& url_examples, size_t trials) {
  std::vector<stat_numbers> numbers(url_examples.size());
  for (size_t i = 0; i < url_examples.size(); i++) {
    numbers[i].url_string = url_examples[i];
    ada::result<result_type> url = ada::parse<result_type>(url_examples[i]);
    if (url) {
      numbers[i].is_valid = true;
      numbers[i].href = url->get_href();
      numbers[i].components = url->get_components();
      numbers[i].has_port = url->has_port();
      numbers[i].has_authority = url->has_authority();
      numbers[i].has_fragment = url->base_fragment_has_value();
      numbers[i].has_search = url->base_search_has_value();
    } else {
      numbers[i].is_valid = false;
    }
  }
  volatile size_t href_size = 0;
  for (size_t i = 0; i < trials; i++) {
    for (stat_numbers& n : numbers) {
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

void print(const stat_numbers& n) {
  std::cout << n.url_string.size() << ",\t\t";
  std::cout << n.counters.best.cycles() << ",\t\t"
            << size_t(n.counters.cycles()) << ",\t\t";
  std::cout << n.counters.best.instructions() << ",\t\t"
            << n.counters.instructions() << ",\t\t";
  // hash size

  std::cout << n.href.size() << ",\t\t";
  size_t end = n.href.size();
  if (n.components.hash_start != ada::url_components::omitted) {
    std::cout << (end - n.components.hash_start) << ",\t\t";
    end = n.components.hash_start;
  } else {
    std::cout << 0 << ",\t\t";
  }
  // search size
  if (n.components.search_start != ada::url_components::omitted) {
    std::cout << (end - n.components.search_start) << ",\t\t";
    end = n.components.search_start;
  } else {
    std::cout << 0 << ",\t\t";
  }
  // path size
  std::cout << (end - n.components.pathname_start) << ",\t\t";
  end = n.components.pathname_start;
  // port size
  std::cout << (end - n.components.host_end) << ",\t\t";
  end = n.components.host_end;
  // host size
  std::cout << (end - n.components.host_start) << ",\t\t";
  end = n.components.host_start;
  // user/pass size
  std::cout << (end - n.components.protocol_end) << ",\t\t";
  end = n.components.protocol_end;
  // protocol type
  ada::result<ada::url_aggregator> url =
      ada::parse<ada::url_aggregator>(n.url_string);
  if (url) {
    std::cout << int(url->type);
  } else {
    std::cout << -1;
  }
  std::cout  << ",\t\t";
  std::cout << n.has_port << ",\t\t";
  std::cout << n.has_authority << ",\t\t";
  std::cout << n.has_fragment << ",\t\t";
  std::cout << n.has_search << ",\t\t";
  std::cout << count_ascii_bytes(n.url_string);


}
void print(const std::vector<stat_numbers> numbers) {
  std::cout << "input_size,\t";
  std::cout << "best_cycles,\tmean_cycles,\t";
  std::cout << "best_instr,\tmean_instr,\t";
  std::cout << "href_size,\thash_size,\tsearch_size,\tpath_size,\tport_size,\thost_size,"
               "\tcredential,\tprotocol,\thas_port,\thas_authority,\thas_fragment,\thas_search,\tascii_bytes";
  std::cout << std::endl;

  for (const stat_numbers& n : numbers) {
    print(n);
    std::cout << std::endl;
  }
}

int main(int argc, char** argv) {
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
  size_t trials = 30;
  std::cout << "# trials " << trials << std::endl;
  if(use_ada_url) {
    std::cout << "# ada::url"<< std::endl;
    print(collect_values<ada::url>(input_urls, trials));
  } else {
    std::cout << "# ada::url_aggregator"<< std::endl;
    print(collect_values<ada::url_aggregator>(input_urls, trials));
  }

  return EXIT_SUCCESS;
}
