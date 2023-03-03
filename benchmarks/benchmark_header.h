#include <iostream>
#include <memory>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <filesystem>

#if ADA_VARIOUS_COMPETITION_ENABLED
#include <uriparser/Uri.h>
#include <EdUrlParser.h>
#include <http_parser.h>
#endif
#if ADA_url_whatwg_ENABLED
#include <src/url.h>
#endif

#include "ada.h"
#include "performancecounters/event_counter.h"
event_collector collector;
size_t N = 1000;

#include <benchmark/benchmark.h>


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

std::vector<std::string> split_string(const std::string& str) {
  auto result = std::vector<std::string>{};
  auto ss = std::stringstream{str};
  for (std::string line; std::getline(ss, line, '\n');) {
    result.push_back(line);
  }
  return result;
}