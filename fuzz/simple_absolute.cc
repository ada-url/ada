#include <fuzzer/FuzzedDataProvider.h>

#include <cstdio>
#include <string>
#include <string_view>

#include "ada.cpp"
#include "ada.h"

// ============================================================
// Fuzzer for the simple-absolute http(s) parse fast path
// (try_parse_simple_absolute) and its intentional fall-throughs:
// digit-led hosts (IPv4), credentials, ports, xn--/IDNA, dot
// segments, percent-encoded dots, and get_href hot-path size.
// ============================================================

static constexpr const char* kSchemes[] = {
    "http://", "https://", "HTTP://", "Https://",
    "http:",   "https:",   "htTP://", "HTTPS://"};

static constexpr const char* kHosts[] = {
    "example.com",
    "www.example.com",
    "WWW.Example.COM",
    "a",
    "a.b.c",
    "maps.google.com",
    "192.168.0.1",  // digit-led host -> IPv4 gate
    "0x7f.1",
    "127.1",
    "0",
    "3232235777",
    "xn--nxasmq6b.com",
    "xn--a",
    "XN--A",
    "user@example.com",
    "user:pass@example.com",
    "example.com:8080",
    "example.com:0",
    "example.com:65535",
    "",
};

static constexpr const char* kPaths[] = {
    "",
    "/",
    "/path",
    "/path/file.js",
    "/a/./b/../c",
    "/foo/%2e",
    "/foo/%2e%2e",
    "/foo/%2E%2E/bar",
    "/path with space",
    "/path\twith\ttab",
    "\\path",
    "/continue=https%3A%2F%2Fexample.com%2F",
    "/imghp",
    "/./",
    "/../",
    "/%2e%2e%2f",
};

static constexpr const char* kQueries[] = {
    "",
    "?",
    "?q=1",
    "?hl=en&tab=wi",
    "?continue=https%3A%2F%2Fexample.com%2F",
    "?a=1&b=2&c=3",
};

static constexpr const char* kFrags[] = {
    "", "#", "#frag", "#x%20y", "#/",
};

template <size_t N>
static const char* pick(FuzzedDataProvider& fdp, const char* const (&arr)[N]) {
  return arr[fdp.ConsumeIntegralInRange<size_t>(0, N - 1)];
}

static std::string make_candidate(FuzzedDataProvider& fdp) {
  std::string out;
  out += pick(fdp, kSchemes);
  out += pick(fdp, kHosts);
  out += pick(fdp, kPaths);
  out += pick(fdp, kQueries);
  out += pick(fdp, kFrags);

  // Optional splice of raw fuzz bytes to widen coverage.
  if (fdp.ConsumeBool() && !out.empty()) {
    std::string mid = fdp.ConsumeRandomLengthString(24);
    size_t pos = fdp.ConsumeIntegralInRange<size_t>(0, out.size());
    out.insert(pos, mid);
  }

  // Optional single-byte mutation.
  if (fdp.ConsumeBool() && !out.empty()) {
    size_t i = fdp.ConsumeIntegralInRange<size_t>(0, out.size() - 1);
    out[i] = static_cast<char>(fdp.ConsumeIntegral<uint8_t>());
  }

  return out;
}

static void check_href_size(const ada::url& u, std::string_view input) {
  if (u.get_href_size() != u.get_href().size()) {
    printf(
        "get_href_size mismatch (url)\n"
        "  input: %.*s\n"
        "  size:  %zu href.size: %zu\n"
        "  href:  %s\n",
        static_cast<int>(input.size()), input.data(), u.get_href_size(),
        u.get_href().size(), u.get_href().c_str());
    abort();
  }
}

static void check_href_size(const ada::url_aggregator& u,
                            std::string_view input) {
  if (u.get_href_size() != u.get_href().size()) {
    printf(
        "get_href_size mismatch (aggregator)\n"
        "  input: %.*s\n"
        "  size:  %zu href.size: %zu\n"
        "  href:  %s\n",
        static_cast<int>(input.size()), input.data(), u.get_href_size(),
        u.get_href().size(), std::string(u.get_href()).c_str());
    abort();
  }
}

template <class Result>
static void check_reparse_idempotent(const Result& parsed,
                                     std::string_view input) {
  const std::string href = std::string(parsed.get_href());
  auto again = ada::parse<Result>(href);
  if (!again) {
    printf(
        "re-parse of href failed\n"
        "  input: %.*s\n"
        "  href:  %s\n",
        static_cast<int>(input.size()), input.data(), href.c_str());
    abort();
  }
  if (std::string(again->get_href()) != href) {
    printf(
        "href not idempotent\n"
        "  input: %.*s\n"
        "  href1: %s\n"
        "  href2: %s\n",
        static_cast<int>(input.size()), input.data(), href.c_str(),
        std::string(again->get_href()).c_str());
    abort();
  }
}

static void check_components_agree(const ada::url& u,
                                   const ada::url_aggregator& a,
                                   std::string_view input) {
  if (u.get_protocol() != a.get_protocol() ||
      u.get_href() != std::string(a.get_href()) ||
      std::string(u.get_hostname()) != std::string(a.get_hostname()) ||
      std::string(u.get_pathname()) != std::string(a.get_pathname()) ||
      std::string(u.get_search()) != std::string(a.get_search()) ||
      std::string(u.get_hash()) != std::string(a.get_hash()) ||
      std::string(u.get_port()) != std::string(a.get_port()) ||
      u.get_username() != std::string(a.get_username()) ||
      u.get_password() != std::string(a.get_password()) ||
      std::string(u.get_host()) != std::string(a.get_host())) {
    printf(
        "url vs aggregator component mismatch\n"
        "  input: %.*s\n"
        "  url href: %s\n"
        "  agg href: %s\n",
        static_cast<int>(input.size()), input.data(), u.get_href().c_str(),
        std::string(a.get_href()).c_str());
    abort();
  }
}

static void fuzz_one_input(std::string_view input) {
  auto url = ada::parse<ada::url>(input);
  auto agg = ada::parse<ada::url_aggregator>(input);

  if (url.has_value() != agg.has_value()) {
    printf(
        "parse agreement failure\n"
        "  input: %.*s\n"
        "  url: %d aggregator: %d\n",
        static_cast<int>(input.size()), input.data(), url.has_value(),
        agg.has_value());
    abort();
  }

  if (!url) {
    return;
  }

  check_components_agree(*url, *agg, input);
  check_href_size(*url, input);
  check_href_size(*agg, input);
  check_reparse_idempotent(*url, input);
  check_reparse_idempotent(*agg, input);

  // get_href hot path must stay consistent after set_href of the same href.
  const std::string href = url->get_href();
  url->set_href(href);
  agg->set_href(href);
  if (url->get_href() != std::string(agg->get_href())) {
    printf(
        "set_href agreement failure\n"
        "  href: %s\n",
        href.c_str());
    abort();
  }
  check_href_size(*url, href);
  check_href_size(*agg, href);

  volatile bool valid = agg->validate();
  (void)valid;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // 1) Structured candidate aimed at the simple-absolute fast path / gates.
  std::string structured = make_candidate(fdp);
  fuzz_one_input(structured);

  // 2) Raw fuzz bytes as a pure absolute-URL-shaped input (prefix http(s)).
  if (fdp.remaining_bytes() > 0) {
    std::string raw = fdp.ConsumeRemainingBytesAsString();
    if (raw.size() > 512) {
      raw.resize(512);
    }
    // Occasionally force an http(s) prefix so the fast-path entry is reached.
    if (!raw.empty() && (static_cast<unsigned char>(raw[0]) & 1u)) {
      raw = std::string("https://") + raw;
    } else if (!raw.empty()) {
      raw = std::string("http://") + raw;
    }
    fuzz_one_input(raw);
  }

  // 3) Fixed seeds that must always be safe (dictionary-like corpus anchors).
  static constexpr const char* kAnchors[] = {
      "https://example.com",
      "https://example.com/",
      "https://example.com?q=1",
      "https://example.com#frag",
      "https://example.com/?q=1#frag",
      "http://www.example.com/path/file.js",
      "http://WWW.Example.COM/file.js",
      "https://www.google.com/imghp?hl=en&tab=wi",
      "http://192.168.0.1/x",
      "http://0x7f.1/",
      "https://user:pass@example.com/x",
      "https://example.com:8080/x",
      "https://example.com/a/./b/../c",
      "https://example.com/foo/%2e%2e",
      "https://xn--nxasmq6b.com/",
      "https://xn--a/",
  };
  for (const char* seed : kAnchors) {
    fuzz_one_input(seed);
  }

  return 0;
}
