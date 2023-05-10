#include <chrono>
#include <cxxopts.hpp>
#include <fstream>
#include <fmt/os.h>

#include "ada.h"
#include "line_iterator.h"
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

template <typename Callable>
bool print_part(Callable&& fmt_or_adaparse_print, std::string_view get_part,
                const ada::url_aggregator& url) {
  if (get_part.size() == 4) {
    if (get_part[0] == 'h') {
      if (get_part == "host") {
        fmt_or_adaparse_print("{}\n", url.get_host());
        return true;
      } else if (get_part == "hash") {
        fmt_or_adaparse_print("{}\n", url.get_hash());
        return true;
      }
    } else if (get_part[0] == 'p') {
      if (get_part == "port") {
        fmt_or_adaparse_print("{}\n", url.get_port());
        return true;
      }
    }
  } else if (get_part.size() == 6) {
    if (get_part == "origin") {
      fmt_or_adaparse_print("{}\n", url.get_origin());
      return true;
    }
    if (get_part == "search") {
      fmt_or_adaparse_print("{}\n", url.get_search());
      return true;
    }
  } else if (get_part.size() == 8) {
    if (get_part[0] == 'p') {
      if (get_part == "protocol") {
        fmt_or_adaparse_print("{}\n", url.get_protocol());
        return true;
      }
      if (get_part == "password") {
        fmt_or_adaparse_print("{}\n", url.get_password());
        return true;
      }
      if (get_part == "pathname") {
        fmt_or_adaparse_print("{}\n", url.get_pathname());
        return true;
      }
    }
  } else if (get_part == "hostname") {
    fmt_or_adaparse_print("{}\n", url.get_hostname());
    return true;

  } else if (get_part == "username") {
    fmt_or_adaparse_print("{}\n", url.get_username());
    return true;
  }

  fmt::print(stderr, "\"{}\" not found\n", get_part);
  return false;
}

// This function parses a FILE * descriptor, line by line (URL by URL).It
// applies the given Callable (in this case the lambda adaparse_print in the
// main() function) to print the output either to a file on disk or to the
// console, depending on arguments given.
// It also optionally will output a benchmark to the console.
template <typename Callable>
int piped_file(Callable&& adaparse_print, const cxxopts::ParseResult result,
               FILE* input_file) {
  constexpr size_t cache_length = 32768;
  std::unique_ptr<char[]> cachebuffer(new char[cache_length]{});

  uint64_t before = nano();

  size_t total_bytes_read = 0;
  size_t bytes_read_this_loop_iteration;
  size_t offset = 0;
  size_t lines = 0;
  size_t sum_of_lines_bytes = 0;
  size_t blocks = 0;

  std::string get_part;
  if (result.count("get")) {
    get_part = result["get"].as<std::string>();
  }

  // Get the file descriptor from the FILE * input_file
#ifdef _MSC_VER
  int input_fd = _fileno(input_file);
#else
  int input_fd = fileno(input_file);
#endif

#ifdef _MSC_VER
  while ((bytes_read_this_loop_iteration =
              _read(input_fd, cachebuffer.get() + offset,
                    (unsigned int)(cache_length - offset)))) {
#else
  while ((bytes_read_this_loop_iteration = read(
              input_fd, cachebuffer.get() + offset, cache_length - offset))) {
#endif
    total_bytes_read += bytes_read_this_loop_iteration;
    blocks++;
    size_t capacity = bytes_read_this_loop_iteration + offset;
    line_iterator li(cachebuffer.get(), capacity);

    while (li.find_another_complete_line()) {
      std::string_view line = li.grab_line();

      ada::result<ada::url_aggregator> url = ada::parse(line);
      if (!url) {
        adaparse_print("Invalid URL:{}\n", line);

      } else if (result.count("get")) {
        std::string get_part = result["get"].as<std::string>();
        print_part(adaparse_print, get_part, url.value());
      }

      else {
        adaparse_print("{}\n", url->get_href());
      }

      lines++;
    }
    if ((offset = li.tail()) > 0) {
      memmove(cachebuffer.get(), cachebuffer.get() + capacity - offset, offset);
    }
  }
  if (offset > 0) {
    // have a line of length offset at cachebuffer.get()
    lines++;
  }

  if (result.count("benchmark")) {
    uint64_t after = nano();
    double giga = total_bytes_read / 1000000000.;

    fmt::print(
        "read {} bytes in {} ns using {} lines, used {} "
        "loads\n",
        total_bytes_read, (after - before), lines, blocks);

    double seconds = (after - before) / 1000000000.;
    double speed = giga / seconds;
    fmt::print("{} GB/s", speed);
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
      "g,get", "Get a specific part of the URL (e.g., 'origin', 'host', etc.)",
      cxxopts::value<std::string>())(
      "b,benchmark", "Display chronometer for piped_file function",
      cxxopts::value<bool>()->default_value("false"))(
      "p,path", "Takes in a path to a file and process all the URL within",
      cxxopts::value<std::string>())(
      "o,output", "Takes in a path and outputs to a text file.",
      cxxopts::value<std::string>()->default_value("__no_output__"))

      ;
  options.parse_positional({"url"});

  auto result = options.parse(argc, argv);

  std::string output_filename = result["output"].as<std::string>();

  result["output"].as<std::string>() == "__no_output__"
      ? output_filename = "/dev/null"
      : output_filename = result["output"].as<std::string>();

  auto out = fmt::output_file(output_filename);

  auto adaparse_print = [&result, &out](const std::string& format_str,
                                        auto&&... args) {
    std::string formatted_str =
        fmt::format(format_str, std::forward<decltype(args)>(args)...);
    if (result.count("output")) {
      out.print(formatted_str);
    } else {
      fmt::print("{}", formatted_str);
    }
  };

#ifdef _MSC_VER
  if (!_isatty(_fileno(stdin))) {
#else
  if (!isatty(fileno(stdin))) {
#endif
    return piped_file(adaparse_print, result, stdin) ? EXIT_SUCCESS
                                                     : EXIT_FAILURE;
  }

  if (result.count("path")) {
    std::string filepath = result["path"].as<std::string>();
    FILE* file = fopen(filepath.c_str(), "r");
    if (file) {
      piped_file(adaparse_print, result, file);
      fclose(file);
      return EXIT_SUCCESS;
    } else {
      int err = errno;
      fmt::print(stderr, "Error opening file: {}\n", strerror(err));
      return EXIT_FAILURE;
    }
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

    auto print_lambda = [](const std::string& format_str, auto&&... args) {
      fmt::print(format_str, std::forward<decltype(args)>(args)...);
    };

    return print_part(print_lambda, get_part, url.value()) ? EXIT_SUCCESS
                                                           : EXIT_FAILURE;
  };
  if (to_diagram) {
    fmt::print("{}\n", url->to_diagram());
  } else {
    fmt::print("{}\n", url->to_string());
  }

  return EXIT_SUCCESS;
}
