#include "ada.h"
#include <iostream>
#include <limits>
#include <memory>
#include <bit>

std::string url_examples[] = {
    "https://www.google.com/"
    "webhp?hl=en&amp;ictx=2&amp;sa=X&amp;ved=0ahUKEwil_"
    "oSxzJj8AhVtEFkFHTHnCGQQPQgI",
    "https://support.google.com/websearch/"
    "?p=ws_results_help&amp;hl=en-CA&amp;fg=1",
    "https://en.wikipedia.org/wiki/Dog#Roles_with_humans",
    "https://www.tiktok.com/@aguyandagolden/video/7133277734310038830",
    "https://business.twitter.com/en/help/troubleshooting/"
    "how-twitter-ads-work.html?ref=web-twc-ao-gbl-adsinfo&utm_source=twc&utm_"
    "medium=web&utm_campaign=ao&utm_content=adsinfo",
    "https://images-na.ssl-images-amazon.com/images/I/"
    "41Gc3C8UysL.css?AUIClients/AmazonGatewayAuiAssets",
    "https://www.reddit.com/?after=t3_zvz1ze",
    "https://www.reddit.com/login/?dest=https%3A%2F%2Fwww.reddit.com%2F",
    "postgresql://other:9818274x1!!@localhost:5432/"
    "otherdb?connect_timeout=10&application_name=myapp",
    "http://192.168.1.1",             // ipv4
    "http://[2606:4700:4700::1111]",  // ipv6
    "https://static.files.bbci.co.uk/orbit/737a4ee2bed596eb65afc4d2ce9af568/js/"
    "polyfills.js",
    "https://static.files.bbci.co.uk/orbit/737a4ee2bed596eb65afc4d2ce9af568/"
    "css/orbit-v5-ltr.min.css",
    "https://static.files.bbci.co.uk/orbit/737a4ee2bed596eb65afc4d2ce9af568/js/"
    "require.min.js",
    "https://static.files.bbci.co.uk/fonts/reith/2.512/BBCReithSans_W_Rg.woff2",
    "https://nav.files.bbci.co.uk/searchbox/c8bfe8595e453f2b9483fda4074e9d15/"
    "css/box.css",
    "https://static.files.bbci.co.uk/cookies/d3bb303e79f041fec95388e04f84e716/"
    "cookie-banner/cookie-library.bundle.js",
    "https://static.files.bbci.co.uk/account/id-cta/597/style/id-cta.css",
    "https://gn-web-assets.api.bbc.com/wwhp/"
    "20220908-1153-091014d07889c842a7bdc06e00fa711c9e04f049/responsive/css/"
    "old-ie.min.css",
    "https://gn-web-assets.api.bbc.com/wwhp/"
    "20220908-1153-091014d07889c842a7bdc06e00fa711c9e04f049/modules/vendor/"
    "bower/modernizr/modernizr.js",
    "https://example.com",
    "https://example.com/",
    "https://example.com?q=1",
    "https://example.com#frag",
    "https://example.com/?q=1#frag",
    "http://www.example.com/path/file.js",
    "https://www.google.com/imghp?hl=en&tab=wi",
    "https://maps.google.com/maps?hl=en&tab=wl",
    "http://WWW.Example.COM/file.js",
    "http://192.168.0.1/x",
    "http://0x7f.1/",
    "https://user@example.com/",
    "https://example.com:8080/x",
    "https://example.com/a/./b/../c",
    "https://example.com/foo/%2e%2e",
    "https://xn--nxasmq6b.com/",
};

// This function copies your input onto a memory buffer that
// has just the necessary size. This will entice tools to detect
// an out-of-bound access.
template <class result>
ada::result<result> ada_parse(std::string_view view) {
  std::unique_ptr<char[]> buffer(new char[view.size()]);
  memcpy(buffer.get(), view.data(), view.size());
  return ada::parse<result>(std::string_view(buffer.get(), view.size()));
}

template <class result>
size_t fancy_fuzz(size_t N, size_t seed = 0) {
  size_t counter = seed;
  for (size_t trial = 0; trial < N; trial++) {
    std::string copy =
        url_examples[(seed++) % (sizeof(url_examples) / sizeof(std::string))];
    auto url = ada::parse<result>(copy);
    while (url) {
      // mutate the string.
      int k = ((321321 * counter++) % 3);
      switch (k) {
        case 0:
          copy.erase((11134 * counter++) % copy.size());
          break;
        case 1:
          copy.insert(copy.begin() + (211311 * counter) % copy.size(),
                      char((counter + 1) * 777));
          counter += 2;
          break;
        case 2:
          copy[(13134 * counter++) % copy.size()] = char(counter++ * 71117);
          break;
        default:
          break;
      }
      url = ada_parse<result>(copy);
    }
  }
  return counter;
}

template <class result>
size_t simple_fuzz(size_t N, size_t seed = 0) {
  size_t counter = seed;
  for (size_t trial = 0; trial < N; trial++) {
    std::string copy =
        url_examples[(seed++) % (sizeof(url_examples) / sizeof(std::string))];
    auto url = ada::parse<result>(copy);
    while (url) {
      // mutate the string.
      copy[(13134 * counter++) % copy.size()] = char(counter++ * 71117);
      url = ada_parse<result>(copy);
    }
  }
  return counter;
}

template <class result>
size_t roller_fuzz(size_t N) {
  size_t valid{};

  for (std::string copy : url_examples) {
    for (size_t index = 0; index < copy.size(); index++) {
      char orig = copy[index];
      for (unsigned int value = 0; value < 255; value++) {
        copy[index] = char(value);
        auto url = ada_parse<result>(copy);
        if (url) {
          valid++;
        }
      }
      copy[index] = orig;
    }
  }
  return valid;
}

// Fuzz with a tight URL size limit (512 bytes). Parses each example URL,
// then applies a sequence of pseudo-random setter calls with mutated values.
// After every operation the href must not exceed the limit.
template <class result>
size_t length_fuzz(size_t N, size_t seed = 0) {
  static constexpr uint32_t kMaxLength = 512;
  ada::set_max_input_length(kMaxLength);

  size_t counter = seed;
  size_t checked = 0;

  auto check = [&](const result& url, const char* context) {
    if (url.get_href_size() > kMaxLength) {
      std::cerr << "length_fuzz FAIL [" << context
                << "]: href_size=" << url.get_href_size() << " exceeds limit "
                << kMaxLength << "\n";
      std::abort();
    }
    checked++;
  };

  for (size_t trial = 0; trial < N; trial++) {
    std::string base_str = url_examples[(seed + trial) % (sizeof(url_examples) /
                                                          sizeof(std::string))];

    // Parse must respect the limit.
    auto url = ada::parse<result>(base_str);
    if (url) {
      check(*url, "parse");
    }

    // Start from a short URL and apply mutated setters.
    auto target = ada::parse<result>("http://x/");
    if (!target) continue;

    for (int step = 0; step < 20; step++) {
      // Build a pseudo-random value: take a slice of a URL example, possibly
      // containing characters that trigger percent-encoding expansion.
      std::string val = url_examples[(counter++) % (sizeof(url_examples) /
                                                    sizeof(std::string))];
      // Mutate: insert characters that expand under percent-encoding.
      size_t insert_pos = (counter * 7) % (val.size() + 1);
      size_t insert_len = (counter * 13) % 256;
      char insert_char = char((counter * 31) & 0xFF);
      val.insert(insert_pos, insert_len, insert_char);
      counter++;

      int which = (counter++) % 10;
      switch (which) {
        case 0:
          target->set_protocol(val);
          break;
        case 1:
          target->set_username(val);
          break;
        case 2:
          target->set_password(val);
          break;
        case 3:
          target->set_hostname(val);
          break;
        case 4:
          target->set_host(val);
          break;
        case 5:
          target->set_pathname(val);
          break;
        case 6:
          target->set_search(val);
          break;
        case 7:
          target->set_hash(val);
          break;
        case 8:
          target->set_port(val);
          break;
        case 9:
          target->set_href(val);
          break;
      }
      check(*target, "setter");
    }
  }

  ada::set_max_input_length(std::numeric_limits<uint32_t>::max());
  return checked;
}

static const char* kSimpleAbsoluteSeeds[] = {
    "https://example.com",
    "https://example.com/",
    "https://example.com/path",
    "https://example.com/path?q=1",
    "https://example.com/path#frag",
    "https://example.com/?q=1#frag",
    "http://www.example.com/file.js",
    "https://www.google.com/imghp?hl=en&tab=wi",
    "http://WWW.Example.COM/file.js",
    "https://example.com/continue=https%3A%2F%2Fexample.com%2F",
    "http://192.168.0.1/x",
    "http://0x7f.0.0.1/",
    "https://user:pass@example.com/x",
    "https://example.com:8080/x",
    "https://example.com/a/./b/../c",
    "https://example.com/foo/%2e",
    "https://example.com/foo/%2e%2e",
    "https://xn--nxasmq6b.com/",
    "https://example.com/path with space",
    "https://example.com/path\twith\ttab",
    "http://example.com\\path",
    "https://example.com?",
    "https://example.com#",
    "https://",
    "http://",
    "https://a",
    "http://a.b.c.d.e.f.g/",
};

template <class R>
static void check_simple_absolute_invariants(const R& parsed,
                                             std::string_view input) {
  const std::string href = std::string(parsed.get_href());
  if (parsed.get_href_size() != href.size()) {
    std::cerr << "simple_absolute_fuzz FAIL get_href_size mismatch\n"
              << "  input: " << input << "\n"
              << "  href:  " << href << "\n"
              << "  size:  " << parsed.get_href_size()
              << " vs href.size()=" << href.size() << "\n";
    std::abort();
  }
  auto reparsed = ada::parse<R>(href);
  if (!reparsed) {
    std::cerr << "simple_absolute_fuzz FAIL re-parse of href\n"
              << "  input: " << input << "\n"
              << "  href:  " << href << "\n";
    std::abort();
  }
  if (std::string(reparsed->get_href()) != href) {
    std::cerr << "simple_absolute_fuzz FAIL href not idempotent\n"
              << "  input: " << input << "\n"
              << "  href1: " << href << "\n"
              << "  href2: " << reparsed->get_href() << "\n";
    std::abort();
  }
}

size_t simple_absolute_fuzz(size_t N, size_t seed = 0) {
  size_t counter = seed;
  size_t checked = 0;
  constexpr size_t nseeds =
      sizeof(kSimpleAbsoluteSeeds) / sizeof(kSimpleAbsoluteSeeds[0]);

  for (size_t trial = 0; trial < N; trial++) {
    std::string copy = kSimpleAbsoluteSeeds[(seed + trial) % nseeds];

    int muts = 1 + int((counter * 17) % 6);
    for (int m = 0; m < muts && !copy.empty(); m++) {
      int kind = int((counter * 31 + m) % 5);
      switch (kind) {
        case 0:
          copy[(counter * 13) % copy.size()] =
              char((counter * 71117 + m) & 0xFF);
          break;
        case 1:
          if (copy.size() > 1) {
            copy.erase((counter * 11) % copy.size(), 1);
          }
          break;
        case 2: {
          static const char specials[] = {':', '@', '/',  '\\', '?',  '#',
                                          '.', '%', '0',  'x',  'A',  '[',
                                          ']', ' ', '\t', '\n', '\r', 0};
          char c = specials[(counter * 7 + m) % (sizeof(specials) - 1)];
          copy.insert(copy.begin() + ((counter * 3) % (copy.size() + 1)), c);
          break;
        }
        case 3: {
          static const char* tails[] = {"/",    "?q=1", "#f", "/./x", "/../y",
                                        "/%2e", ":80",  "@u", "0",    "xn--a"};
          copy += tails[(counter + m) % 10];
          break;
        }
        case 4: {
          static const char* prefixes[] = {"http://",  "https://", "HTTP://",
                                           "Https://", "http:",    "https:"};
          if (copy.rfind("http", 0) == 0) {
            auto pos = copy.find("://");
            if (pos != std::string::npos) {
              copy = copy.substr(pos + 3);
            }
          }
          copy = std::string(prefixes[(counter + m) % 6]) + copy;
          break;
        }
        default:
          break;
      }
      counter++;
    }

    auto u = ada_parse<ada::url>(copy);
    auto a = ada_parse<ada::url_aggregator>(copy);
    if (u.has_value() != a.has_value()) {
      std::cerr << "simple_absolute_fuzz FAIL parse agreement\n"
                << "  input: " << copy << "\n"
                << "  url: " << u.has_value()
                << " aggregator: " << a.has_value() << "\n";
      std::abort();
    }
    if (u) {
      if (u->get_href() != std::string(a->get_href())) {
        std::cerr << "simple_absolute_fuzz FAIL href mismatch\n"
                  << "  input: " << copy << "\n"
                  << "  url:  " << u->get_href() << "\n"
                  << "  agg:  " << a->get_href() << "\n";
        std::abort();
      }
      check_simple_absolute_invariants(*u, copy);
      check_simple_absolute_invariants(*a, copy);
      checked++;
    }
  }
  return checked;
}

size_t simple_absolute_roller_fuzz() {
  size_t valid = 0;
  constexpr size_t nseeds =
      sizeof(kSimpleAbsoluteSeeds) / sizeof(kSimpleAbsoluteSeeds[0]);
  for (size_t s = 0; s < nseeds; s++) {
    std::string copy = kSimpleAbsoluteSeeds[s];
    for (size_t index = 0; index < copy.size(); index++) {
      char orig = copy[index];
      for (unsigned int value = 0; value < 255; value++) {
        copy[index] = char(value);
        auto u = ada_parse<ada::url>(copy);
        auto a = ada_parse<ada::url_aggregator>(copy);
        if (u.has_value() != a.has_value()) {
          std::cerr << "simple_absolute_roller FAIL parse agreement\n"
                    << "  input: " << copy << "\n";
          std::abort();
        }
        if (u) {
          if (u->get_href() != std::string(a->get_href())) {
            std::cerr << "simple_absolute_roller FAIL href mismatch\n"
                      << "  input: " << copy << "\n"
                      << "  url:  " << u->get_href() << "\n"
                      << "  agg:  " << a->get_href() << "\n";
            std::abort();
          }
          valid++;
        }
      }
      copy[index] = orig;
    }
  }
  return valid;
}

int main() {
  if (std::endian::native == std::endian::big) {
    std::cout << "You have big-endian system." << std::endl;
  } else {
    std::cout << "You have litte-endian system." << std::endl;
  }
  std::cout << "Running basic fuzzer.\n";
  std::cout << "[fancy]  Executed " << fancy_fuzz<ada::url>(100000)
            << " mutations.\n";
  std::cout << "[simple] Executed " << simple_fuzz<ada::url>(40000)
            << " mutations.\n";
  std::cout << "[roller] Executed " << roller_fuzz<ada::url>(40000)
            << " correct cases.\n";
  std::cout << "[fancy]  Executed " << fancy_fuzz<ada::url_aggregator>(100000)
            << " mutations.\n";
  std::cout << "[simple] Executed " << simple_fuzz<ada::url_aggregator>(40000)
            << " mutations.\n";
  std::cout << "[roller] Executed " << roller_fuzz<ada::url_aggregator>(40000)
            << " correct cases.\n";
  std::cout << "[length] Checked " << length_fuzz<ada::url>(10000)
            << " length invariants.\n";
  std::cout << "[length] Checked " << length_fuzz<ada::url_aggregator>(10000)
            << " length invariants.\n";
  std::cout << "[simple_abs] Checked " << simple_absolute_fuzz(80000)
            << " successful parses.\n";
  std::cout << "[simple_abs_roller] Valid " << simple_absolute_roller_fuzz()
            << " cases.\n";
  return EXIT_SUCCESS;
}
