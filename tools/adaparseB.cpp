#include <cstdlib>
#include <chrono>
#include <iostream>
#include <string_view>
#include <sys/stat.h>
#include <fmt/core.h>
#include <cxxopts.hpp>
#include <fstream>
#include "ada.h"
#ifdef _MSC_VER
#include <io.h>
#else
#include <unistd.h>
#endif

uint64_t nano() {
  return std::chrono::duration_cast<::std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}


bool print_part(std::string_view get_part, const ada::url_aggregator& url) {
    if(get_part.size() == 4) {
        if(get_part[0] == 'h') {
          if(get_part == "host") {
            fmt::print("{}\n", url.get_host());
            return true;
          } else if(get_part == "hash") {
            fmt::print("{}\n", url.get_hash());
            return true;
          }
        } else if(get_part[0] == 'p') {
          if(get_part == "port") {
            fmt::print("{}\n", url.get_port());
            return true;
          }
        }
    } else if(get_part.size() == 6) {
        if(get_part == "origin") {
          fmt::print("{}\n", url.get_origin());
          return true;
        }
        if(get_part == "search") {
          fmt::print("{}\n", url.get_search());
          return true;
        }
    } else if(get_part.size() == 7) {
      if(get_part[0] == 'p') {
        if(get_part == "protocol") {
          fmt::print("{}\n", url.get_protocol());
          return true;
        }
        if(get_part == "password") {
          fmt::print("{}\n", url.get_password());
          return true;
        }
        if(get_part == "pathname") {
          fmt::print("{}\n", url.get_pathname());
          return true;
        }

    }
    } else if(get_part == "hostname") {
        fmt::print("{}\n", url.get_hostname());
        return true;

    } else if(get_part == "username") {
        fmt::print("{}\n", url.get_username());
        return true;
    }

    fmt::print(stderr, "\"{}\" not found\n", get_part);
    return false;
}

// Define a function that takes an optional command line argument.
int piped_file(const cxxopts::ParseResult result,std::istream& input_stream) {
  uint64_t before = nano();
  size_t lines = 0;
  // allocate 512k buffer
  size_t total_bytes = 0;
  char *buf = (char *)malloc(1024 * 512);
  size_t count = fread(buf, 1, 1024 * 512, stdin);
  //size_t count = input_stream.read(buf + partial_size, 1024 * 512 - partial_size).gcount(); 
  total_bytes += count;
  ada::result<ada::url_aggregator> url;

  while (count > 0) {
    std::string_view whole(buf, count);
    size_t t = whole.find('\n');
    while (t != std::string_view::npos) {
      std::string_view thisline = whole.substr(0, t);
      lines++;
      url = ada::parse(thisline);
      if (!url) {
        fmt::print(stderr, "Invalid URL: {}\n", thisline);
      } else if (result.count("get")) {
        std::string get_part = result["get"].as<std::string>();
        print_part(get_part, url.value());
      } else {
        fmt::print("{}\n",url->get_href());
      }
      whole.remove_prefix(t + 1); // assume Linux/macos line endings
      if (whole.empty()) {
        t = 0;
        break;
      }
      t = whole.find('\n');
    }
    if (t == std::string_view::npos) {
      // we have a partial line
      // copy it to the beginning of the buffer
      // and read more data
      size_t partial_size = whole.size();
      memcpy(buf, whole.data(), partial_size);
      count = fread(buf + partial_size, 1, 1024 * 512 - partial_size, stdin);
      total_bytes += count;
      count += partial_size;
    } else {
      count = fread(buf, 1, 1024 * 512, stdin);
      total_bytes += count;
    }
  }
  free(buf);

  uint64_t after = nano();

        if (result.count("benchmark")) {
            uint64_t after = nano();
            double giga = total_bytes / 1000000000.;
            fmt::print("read {} bytes in {} ns using {} lines\n", total_bytes, (after - before), lines);
            double seconds = (after - before) / 1000000000.;
            double speed = giga / seconds;
            fmt::print("{} GB/s" , speed);
          }

  return EXIT_SUCCESS;
}



/**
 * @private
 *
 * Running this executable, you can quickly test ada:
 *
 * $ adaparse "http://www.google.com/bal?a==11#fddfds"
 * {
 *       "buffer":"http://www.google.com/bal?a==11#fddfds",
 *       "protocol":"http:",
 *       "host":"www.google.com",
 *       "path":"/bal",
 *       "opaque path":false,
 *       "query":"?a==11",
 *       "fragment":"#fddfds",
 *       "protocol_end":5,
 *       "username_end":7,
 *       "host_start":7,
 *       "host_end":21,
 *       "port":null,
 *       "pathname_start":21,
 *       "search_start":25,
 *       "hash_start":31
 * }
 *
 * $ ./buildbench/tools/adaparse -d http://www.google.com/bal\?a\=\=11\#fddfds
 * http://www.google.com/bal?a==11#fddfds [38 bytes]
 *      | |             |   |     |
 *      | |             |   |     `------ hash_start
 *      | |             |   `------------ search_start 25
 *      | |             `---------------- pathname_start 21
 *      | |             `---------------- host_end 21
 *      | `------------------------------ host_start 7
 *      | `------------------------------ username_end 7
 *      `-------------------------------- protocol_end 5
 **/
int main(int argc, char** argv) {
  std::ios::sync_with_stdio(false);


  cxxopts::Options options("adaparse",
                           "Command-line version of the Ada URL parser");

  options.add_options()("d,diagram", "Print a diagram of the result",
                        cxxopts::value<bool>()->default_value("false"))(
      "u,url", "URL Parameter (required)", cxxopts::value<std::string>())(
      "h,help", "Print usage")(
      "g,get", "Get a specific part of the URL (e.g., 'origin', 'host', etc.)",cxxopts::value<std::string>())(
      "b,benchmark", "Run benchmark for piped file functions",cxxopts::value<bool>()->default_value("false") )(
      //"p,path", "Takes in a path and process all the files within", cxxopts::value<std::string>())(
      "a,alternate", "run alternate function for piped file", cxxopts::value<bool>()->default_value("false") )
      
      ;
  options.parse_positional({"url"});

  auto result = options.parse(argc, argv);
#ifdef _MSC_VER
  if (!_isatty(_fileno(stdin))) {
#else
  if (!isatty(fileno(stdin))) {
#endif
  return piped_file(result,std::cin) ? EXIT_SUCCESS : EXIT_FAILURE;


  /*if (!result.count("alternate")) {
    return piped_file(result,std::cin) ? EXIT_SUCCESS : EXIT_FAILURE;
  } else {
    return piped_file_B(result,std::cin) ? EXIT_SUCCESS : EXIT_FAILURE;
  }*/

  }
  
  // the first argument without an option name will be parsed into file
  if (result.count("help") || !result.count("url")) {
    fmt::print(stderr, "{}\n", options.help());
    return EXIT_SUCCESS;
  }


/* To be completed later? 
  std::ifstream file_stream("linux_files.txt");
  if (file_stream.is_open()) {
    piped_file(result, file_stream);
    file_stream.close();
  } else {
    std::cerr << "Unable to open file input.txt" << std::endl;
  }*/

  std::string url_string = result["url"].as<std::string>();
  bool to_diagram = result["diagram"].as<bool>();


  ada::result<ada::url_aggregator> url = ada::parse(url_string);
  if (!url) {
    fmt::print(stderr, "Invalid URL: {}\n", url_string);
    return EXIT_FAILURE;
  }
  if (result.count("get")) {
    std::string get_part = result["get"].as<std::string>();
    return print_part(get_part, url.value()) ? EXIT_SUCCESS : EXIT_FAILURE;
  };
  if (to_diagram) {
    fmt::print("{}\n", url->to_diagram());
  } else {
    fmt::print("{}\n", url->to_string());
  }

  return EXIT_SUCCESS;
}
