#include "ada.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>

// Tight limit to test enforcement without large allocations.
static constexpr uint32_t kMaxLength = 512;

template <class T>
static void check_length(const T& url, const char* context) {
  if (url.get_href_size() > kMaxLength) {
    fprintf(stderr, "FAIL [%s]: href_size=%zu exceeds limit %u\n", context,
            url.get_href_size(), kMaxLength);
    abort();
  }
}

// Try parsing a string and verify the result (if valid) respects the limit.
template <class T>
static void try_parse(const std::string& input, const char* label) {
  auto result = ada::parse<T>(input);
  if (result) {
    check_length(*result, label);
  }
}

// Try parsing with a base URL.
template <class T>
static void try_parse_with_base(const std::string& input,
                                const std::string& base_str,
                                const char* label) {
  auto base = ada::parse<T>(base_str);
  if (base) {
    auto result = ada::parse<T>(input, &*base);
    if (result) {
      check_length(*result, label);
    }
  }
}

// Apply a setter and verify the URL still respects the limit.
template <class T>
static void try_setters(T& url, const std::string& val) {
  url.set_protocol(val);
  check_length(url, "set_protocol");
  url.set_username(val);
  check_length(url, "set_username");
  url.set_password(val);
  check_length(url, "set_password");
  url.set_hostname(val);
  check_length(url, "set_hostname");
  url.set_host(val);
  check_length(url, "set_host");
  url.set_pathname(val);
  check_length(url, "set_pathname");
  url.set_search(val);
  check_length(url, "set_search");
  url.set_hash(val);
  check_length(url, "set_hash");
  url.set_port(val);
  check_length(url, "set_port");
  url.set_href(val);
  check_length(url, "set_href");
}

int main() {
  ada::set_max_input_length(kMaxLength);

  // --- Corpus of interesting URL strings ---
  // Includes normal URLs, edge cases, percent-encoding triggers, long paths,
  // non-special schemes, and adversarial inputs.
  const std::string inputs[] = {
      // Basic URLs
      "http://x/",
      "https://example.com/path?query=1#hash",
      "ftp://ftp.example.com/pub/file.txt",
      "ws://echo.websocket.org/",
      "wss://secure.example.com:8443/chat",
      "file:///tmp/test.txt",
      // Non-special schemes
      "foo://bar/baz",
      "custom-scheme://host/path",
      // Percent-encoding expansion (spaces -> %20, 3x)
      std::string("http://x/") + std::string(200, ' ') + "y",
      std::string("http://x/") + std::string(170, ' ') + "end",
      // Percent-encoding via braces and angle brackets
      std::string("http://x/") + std::string(200, '{') + "y",
      std::string("http://x/") + std::string(200, '<') + "y",
      // Control characters that get percent-encoded
      std::string("http://x/") + std::string(200, '\x01') + "y",
      std::string("http://x/") + std::string(200, '\x7f') + "y",
      // Long paths (just under and just over the limit)
      "http://x/" + std::string(500, 'a'),
      "http://x/" + std::string(510, 'a'),
      // Long hostnames
      "http://" + std::string(500, 'a') + ".com/",
      // Long query strings
      "http://x/?" + std::string(500, 'q'),
      // Long hash
      "http://x/#" + std::string(500, 'h'),
      // Username/password
      "http://" + std::string(200, 'u') + ":" + std::string(200, 'p') + "@x/",
      // Port edge cases
      "http://x:65535/",
      "http://x:0/",
      // IPv6
      "http://[::1]/path",
      "http://[2001:db8::1]:8080/",
      // Empty components
      "http://x",
      "http://x?",
      "http://x#",
      // Opaque paths
      "data:text/html,<h1>Hello</h1>",
      "javascript:void(0)",
      "mailto:user@example.com",
      // Mixed case scheme
      "HTTP://EXAMPLE.COM/PATH",
      // Relative-looking inputs (parsed as absolute)
      "//example.com/path",
      "../relative/path",
      "/absolute/path",
      // Tab and newline stripping
      "htt\tp://ex\nample.com/pa\rth",
      // Backslash normalization
      "http://x\\path\\to\\file",
      // Dots in paths
      "http://x/a/b/../c/./d/../e",
      // Already-encoded input
      "http://x/%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20"
      "%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20"
      "%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20"
      "%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20"
      "%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20"
      "%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20"
      "%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20"
      "%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20"
      "%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20"
      "%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20"
      "%20%20%20%20%20%20%20y",
  };

  const std::string setter_values[] = {
      "",
      "a",
      std::string(512, 'x'),
      std::string(200, ' '),
      std::string(200, '{'),
      std::string(100, '\x01'),
      "http",
      "https",
      "ftp",
      "wss",
      "custom",
      std::string(300, 'u'),
      "8080",
      "65535",
      "?query=value",
      "#fragment",
      "/path/to/resource",
      std::string(200, '/'),
      std::string(100, '%') + "20",
  };

  printf("Testing parse...\n");
  for (const auto& input : inputs) {
    try_parse<ada::url>(input, "parse<url>");
    try_parse<ada::url_aggregator>(input, "parse<url_aggregator>");
  }

  printf("Testing parse with base...\n");
  const std::string bases[] = {
      "http://x/",
      "https://example.com/a/b/c",
      "foo://bar/baz",
  };
  for (const auto& input : inputs) {
    for (const auto& base : bases) {
      try_parse_with_base<ada::url>(input, base, "parse<url>(base)");
      try_parse_with_base<ada::url_aggregator>(input, base, "parse<agg>(base)");
    }
  }

  printf("Testing setters...\n");
  const std::string start_urls[] = {
      "http://x/",
      "https://user:pass@example.com:8080/path?q=1#frag",
      "foo://bar/baz",
  };
  for (const auto& start : start_urls) {
    for (const auto& val : setter_values) {
      auto u = ada::parse<ada::url>(start);
      auto a = ada::parse<ada::url_aggregator>(start);
      if (u && a) {
        try_setters(*u, val);
        try_setters(*a, val);
      }
    }
  }

  printf("Testing cumulative setters...\n");
  // Apply multiple setter values sequentially to accumulate size.
  for (const auto& start : start_urls) {
    auto u = ada::parse<ada::url>(start);
    auto a = ada::parse<ada::url_aggregator>(start);
    if (!u || !a) continue;
    for (const auto& val : setter_values) {
      u->set_username(val);
      check_length(*u, "cumulative set_username url");
      a->set_username(val);
      check_length(*a, "cumulative set_username agg");

      u->set_pathname(val);
      check_length(*u, "cumulative set_pathname url");
      a->set_pathname(val);
      check_length(*a, "cumulative set_pathname agg");

      u->set_search(val);
      check_length(*u, "cumulative set_search url");
      a->set_search(val);
      check_length(*a, "cumulative set_search agg");

      u->set_hash(val);
      check_length(*u, "cumulative set_hash url");
      a->set_hash(val);
      check_length(*a, "cumulative set_hash agg");
    }
  }

  ada::set_max_input_length(std::numeric_limits<uint32_t>::max());
  printf("All max_length_fuzzer checks passed.\n");
  return 0;
}
