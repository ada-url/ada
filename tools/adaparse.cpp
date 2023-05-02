#include <cstdlib>
#include <iostream>
#include <string_view>
#include <cxxopts.hpp>
#include "ada.h"
#include <unistd.h>

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
              std::cerr << "Invalid URL: " << line << std::endl;
          } else {
              std::cout << url->get_href() << std::endl;
          }
      }
      return EXIT_SUCCESS;
}

  // the first argument without an option name will be parsed into file
  if (result.count("help") || !result.count("url")) {
    std::cout << options.help() << std::endl;
    return EXIT_SUCCESS;
  }

  std::string url_string = result["url"].as<std::string>();
  bool to_diagram = result["diagram"].as<bool>();


  ada::result<ada::url_aggregator> url = ada::parse(url_string);

  std::string get_part;
  if (result.count("get")) {
    get_part = result["get"].as<std::string>();

        std::map<std::string, std::string> getters;

        // Initializing
        getters["origin"] = url -> get_origin();
        getters["protocol"] = url -> get_protocol();
        getters["host"] = url -> get_host();
        getters["hostname"] = url -> get_hostname();
        getters["pathname"] = url -> get_pathname();
        getters["search"] = url -> get_search();
        getters["username"] = url -> get_username();
        getters["password"] = url -> get_password();
        getters["port"] = url -> get_port();
        getters["hash"] = url -> get_hash();

        std::cout << getters[get_part] << std::endl;

        return EXIT_SUCCESS;


       };

    std::string set_part;
if (result.count("set")) {
  set_part = result["set"].as<std::string>();

  std::string set_value;
  if (result.count("value")) {
    set_value = result["value"].as<std::string>();
  } else {
    std::cerr << "Error: No value provided for the setter." << std::endl;
    return EXIT_FAILURE;
  };

/*
  std::map<std::string, std::function<bool(ada::url*, const std::string)>> setters;

  // Initializing
  setters["host"] = &ada::url::set_host;
  setters["hostname"] = &ada::url::set_hostname;
  setters["pathname"] = &ada::url::set_pathname;
  //setters["search"] = &ada::url::set_search;
  setters["username"] = &ada::url::set_username;
  setters["password"] = &ada::url::set_password;
  setters["port"] = &ada::url::set_port;
  //setters["hash"] = &ada::url::set_hash;
  setters["protocol"] = &ada::url::set_protocol;
  setters["href"] = &ada::url::set_href;*/



 /* if (setters.find(set_part) != setters.end()) {
  bool success = 1;//setters[set_part](url.get(), set_value);
    if (success) {
      std::cout << "Successfully set the " << set_part << " to: " << set_value << std::endl;
    } else {
      std::cerr << "Failed to set the " << set_part << " to: " << set_value << std::endl;
      return EXIT_FAILURE;
    }
  } else {
    std::cerr << "Error: Invalid setter name." << std::endl;
    return EXIT_FAILURE;
  }*/

  return EXIT_SUCCESS;
}


  


  if (!url) {
    std::cerr << "Invalid." << std::endl;
    return EXIT_FAILURE;
  }
  if (to_diagram) {
    std::cout << url->to_diagram() << std::endl;
  } else {
    std::cout << *url << std::endl;
  }



  return EXIT_SUCCESS;
}
