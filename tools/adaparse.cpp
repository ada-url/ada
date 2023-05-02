#include <cstdlib>
#include <fmt/core.h>
#include <cxxopts.hpp>
#include "ada.h"
#include <unistd.h>

bool print_part(std::string_view get_part, const ada::url_aggregator& url) {
    if(get_part.size() == 3) {
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
    } else if(get_part.size() == 4) {
        if(get_part == "origin") {
          fmt::print("{}\n", url.get_origin());
          return true;
        }
        if(get_part == "search") {
          fmt::print("{}\n", url.get_search());
          return true;
        }
    } else if(get_part.size() == 5) {
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
      } else if(get_part == "hostname") {
          fmt::print("{}\n", url.get_hostname());
          return true;

      } else if(get_part == "username") {
          fmt::print("{}\n", url.get_username());
          return true;
      }
    }
    fmt::print(stderr, "{}\n", url.get_username());
    return false;
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
  cxxopts::Options options("adaparse",
                           "Command-line version of the Ada URL parser");

  options.add_options()("d,diagram", "Print a diagram of the result",
                        cxxopts::value<bool>()->default_value("false"))(
      "u,url", "URL Parameter (required)", cxxopts::value<std::string>())(
      "h,help", "Print usage")(
      "g,get", "Get a specific part of the URL (e.g., 'origin', 'host', etc.)"
      ,cxxopts::value<std::string>())
      ;
  options.parse_positional({"url"});

  auto result = options.parse(argc, argv);

  if (!isatty(fileno(stdin))) {
      std::string line;
      while (std::getline(std::cin, line)) {
          ada::result<ada::url_aggregator> url = ada::parse(line);
          if (!url) {
              fmt::print(stderr, "Invalid URL: {}\n", line);
          } else {
              fmt::print("{}\n", url->to_string());
          }
      }
      return EXIT_SUCCESS;
}

  // the first argument without an option name will be parsed into file
  if (result.count("help") || !result.count("url")) {
    fmt::print(stderr, "{}\n", options.help());
    return EXIT_SUCCESS;
  }

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
