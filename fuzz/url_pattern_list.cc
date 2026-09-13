#include <fuzzer/FuzzedDataProvider.h>

#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

// The amalgamated ada.cpp carries the route-set compiler
// (src/url_pattern_list_compiler.h), which is not part of the public
// headers; the reference below uses its classification to rank routes.
#include "ada.cpp"
#include "ada.h"

using regex_provider = ada::url_pattern_regex::std_regex_provider;
using list_type = ada::url_pattern_list<regex_provider>;
namespace compiler = ada::url_pattern_list_compiler;
using groups_type = std::vector<std::optional<std::string>>;

// One route of the independent reference: the compiler's classification
// (for the priority order only) and the URLPattern object itself, whose
// pathname component -- ada's own engine, regex_search included -- decides
// whether the route matches and what its group values are.
struct reference_route {
  compiler::route_info info{};
  ada::url_pattern<regex_provider> pattern{};
};

// Mirrors the classification url_pattern_list performs and builds the
// url_pattern oracle. Returns false when a pattern is rejected, in which
// case parse_url_pattern_list must fail too.
static bool build_reference(const std::vector<std::string>& patterns,
                            const ada::url_pattern_options& options,
                            std::vector<reference_route>& out) {
  for (const std::string& pattern : patterns) {
    auto compile_options = ada::url_pattern_compile_component_options::PATHNAME;
    auto part_list = ada::url_pattern_helpers::parse_pattern_string(
        pattern, compile_options,
        ada::url_pattern_helpers::canonicalize_pathname);
    if (!part_list) {
      return false;
    }
    reference_route route{};
    if (compiler::classify_parts(*part_list, route.info.segments,
                                 route.info.group_names)) {
      compiler::finalize_route(route.info);
    } else {
      compiler::approximate_kind_sequence(*part_list, route.info);
    }
    auto parsed = ada::parse_url_pattern<regex_provider>(
        ada::url_pattern_init{.pathname = pattern}, nullptr, &options);
    if (!parsed) {
      return false;
    }
    route.pattern = std::move(*parsed);
    out.push_back(std::move(route));
  }
  return true;
}

// The reference oracle: every route's URLPattern pathname component is
// executed on the raw input (fast_match is exactly what url_pattern::exec
// runs per component: regex_search for regexp components), and the winner
// is the best match under the documented priority rule. Any disagreement
// with url_pattern_list::match is a bug in the compiled tables.
static int32_t reference_match(const std::vector<reference_route>& routes,
                               std::string_view pathname, groups_type& groups) {
  int32_t best_route = -1;
  for (size_t i = 0; i < routes.size(); i++) {
    const reference_route& route = routes[i];
    if (best_route >= 0 &&
        !compiler::route_outranks(route.info, i,
                                  routes[static_cast<size_t>(best_route)].info,
                                  static_cast<size_t>(best_route))) {
      continue;
    }
    auto result = route.pattern.pathname_component.fast_match(pathname);
    if (result) {
      groups = std::move(*result);
      best_route = static_cast<int32_t>(i);
    }
  }
  return best_route;
}

// Walk every field of a match result so nothing the public API hands out is
// left unread under the sanitizers.
static void exercise_match_result(
    const ada::url_pattern_list_match_result& result) {
  volatile uint64_t sink = 0;
  sink += static_cast<uint64_t>(result.route_index);
  sink += result.capture_count;
  sink += result.captures_truncated ? 1 : 0;
  sink += result.regexp_route ? 1 : 0;
  sink += result.has_match() ? 1 : 0;
  for (const auto& capture : result.captures) {
    sink += capture.offset;
    sink += capture.length;
  }
  for (const auto& group : result.regexp_groups) {
    sink += group.has_value() ? group->size() : 0;
  }
  (void)sink;
}

static void fail(const char* what, const std::string& input,
                 const std::vector<std::string>& patterns) {
  printf("url_pattern_list %s on input '%s'\n", what, input.c_str());
  for (const std::string& pattern : patterns) {
    printf("  pattern: '%s'\n", pattern.c_str());
  }
  abort();
}

static void check_agreement(const list_type& list,
                            const std::vector<reference_route>& reference,
                            const std::vector<std::string>& patterns,
                            const std::string& input) {
  // The pathname is handed over as a view of an exactly sized heap buffer
  // (not a null-terminated std::string), so that a read past its end is a
  // heap-buffer-overflow under ASan rather than a silent read of the
  // terminator.
  const std::vector<char> exact(input.begin(), input.end());
  const auto matched = list.match(std::string_view(exact.data(), exact.size()));
  exercise_match_result(matched);
  groups_type expected_groups;
  const int32_t expected_route =
      reference_match(reference, input, expected_groups);
  if (matched.route_index != expected_route) {
    printf("list=%d ref=%d\n", matched.route_index, expected_route);
    fail("winner mismatch", input, patterns);
  }
  if (expected_route < 0) {
    return;
  }
  const reference_route& winner =
      reference[static_cast<size_t>(expected_route)];
  const bool is_regexp =
      winner.info.mode == ada::url_pattern_list_detail::route_mode::regexp;
  if (matched.regexp_route != is_regexp) {
    fail("capture form mismatch", input, patterns);
  }
  if (is_regexp) {
    // Regexp winners: the provider's groups, verbatim.
    if (matched.regexp_groups != expected_groups) {
      fail("regexp group mismatch", input, patterns);
    }
    return;
  }
  // Subset winners: slices of the input equal to the oracle's group values,
  // truncated at max_captures_per_route.
  const size_t n_reported =
      std::min<size_t>(expected_groups.size(),
                       ada::url_pattern_list_limits::max_captures_per_route);
  if (matched.capture_count != n_reported ||
      matched.captures_truncated != (expected_groups.size() > n_reported) ||
      !matched.regexp_groups.empty()) {
    fail("capture count mismatch", input, patterns);
  }
  for (size_t k = 0; k < n_reported; k++) {
    const auto& capture = matched.captures[k];
    if (capture.offset + capture.length > input.size() ||
        !expected_groups[k].has_value() ||
        input.compare(capture.offset, capture.length, *expected_groups[k]) !=
            0) {
      fail("capture slice mismatch", input, patterns);
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  auto to_ascii = [](const std::string& source) -> std::string {
    std::string result;
    result.reserve(source.size());
    for (char c : source) {
      result.push_back(static_cast<unsigned char>(c) % 128);
    }
    return result;
  };
  // Tokens from a canonical-safe alphabet, so structured patterns compile
  // often and derived inputs need no canonicalization. Upper-case letters
  // exercise the ignore_case folding paths.
  auto token = [&fdp]() -> std::string {
    static constexpr char alphabet[] =
        "abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_.~";
    const size_t length = fdp.ConsumeIntegralInRange<size_t>(1, 12);
    std::string result;
    result.reserve(length);
    for (size_t j = 0; j < length; j++) {
      result +=
          alphabet[fdp.ConsumeIntegralInRange<size_t>(0, sizeof(alphabet) - 2)];
    }
    return result;
  };

  // --- strategy (i): construction over 1..64 derived pattern strings -------
  const size_t n_patterns = fdp.ConsumeIntegralInRange<size_t>(1, 64);
  std::vector<std::string> patterns;
  patterns.reserve(n_patterns);
  for (size_t i = 0; i < n_patterns; i++) {
    const int mode = fdp.ConsumeIntegralInRange<int>(0, 6);
    if (mode == 0) {
      // Raw pattern bytes: URLPattern syntax errors are expected and must
      // surface as a clean parse error, never as a crash.
      patterns.push_back("/" + to_ascii(fdp.ConsumeRandomLengthString(40)));
    } else if (mode == 1 && !patterns.empty()) {
      // Duplicate an earlier pattern: the smaller index must win.
      patterns.push_back(
          patterns[fdp.ConsumeIntegralInRange<size_t>(0, patterns.size() - 1)]);
    } else {
      // Structured pattern in (and just beyond) the safe subset.
      std::string pattern;
      const size_t depth = fdp.ConsumeIntegralInRange<size_t>(1, 20);
      int params = 0;
      for (size_t d = 0; d < depth; d++) {
        const int kind = fdp.ConsumeIntegralInRange<int>(0, 11);
        if (kind == 0 && d + 1 == depth) {
          pattern += "/*";
        } else if (kind <= 3) {
          pattern += "/:p" + std::to_string(params++);
        } else if (kind == 4) {
          // Witness-hostile literals: identical first/last windows.
          pattern += "/aaaaaaaa";
          pattern +=
              static_cast<char>('A' + fdp.ConsumeIntegralInRange<int>(0, 25));
          pattern += "aaaaaaaa";
        } else if (kind == 5 && mode == 6) {
          // Regexp-mode routes: custom groups, optional and mixed segments.
          switch (fdp.ConsumeIntegralInRange<int>(0, 3)) {
            case 0:
              pattern += "/(\\d+)";
              break;
            case 1:
              pattern += "/:q" + std::to_string(params++) + "?";
              break;
            case 2:
              pattern += "/x-(\\w+)";
              break;
            default:
              pattern += "/pre-:m" + std::to_string(params++);
              break;
          }
        } else {
          pattern += "/" + token();
        }
      }
      patterns.push_back(std::move(pattern));
    }
  }
  const ada::url_pattern_options options{.ignore_case = fdp.ConsumeBool()};
  std::vector<std::string_view> views(patterns.begin(), patterns.end());
  auto list_result =
      ada::parse_url_pattern_list<regex_provider>(views, nullptr, &options);

  // --- strategy (ii): the independent reference must agree on
  // constructibility, on every winner, and on every capture ---------------
  std::vector<reference_route> reference;
  const bool reference_ok = build_reference(patterns, options, reference);
  if (list_result.has_value() != reference_ok) {
    printf("parse/reference disagreement: parse=%d reference=%d\n",
           list_result.has_value() ? 1 : 0, reference_ok ? 1 : 0);
    abort();
  }
  if (!list_result) {
    return 0;
  }
  const list_type& list = *list_result;

  // Exercise the full public surface.
  volatile uint64_t sink = list.size();
  sink += list.ignore_case() ? 1 : 0;
  bool has_regexp_route = false;
  for (size_t i = 0; i < list.size(); i++) {
    sink += list.pattern(i).size();
    for (const std::string& name : list.group_names(i)) {
      sink += name.size();
    }
    has_regexp_route |= reference[i].info.mode ==
                        ada::url_pattern_list_detail::route_mode::regexp;
  }
  (void)sink;

  const size_t n_inputs = fdp.ConsumeIntegralInRange<size_t>(1, 8);
  for (size_t u = 0; u < n_inputs; u++) {
    std::string input;
    const int strategy = fdp.ConsumeIntegralInRange<int>(0, 9);
    if (strategy >= 8 && !has_regexp_route) {
      // --- strategy (iii): fast-path-gate crossings. Only exact for the
      // regex-free subset, where long inputs cannot make std::regex
      // pathological. ---
      if (fdp.ConsumeBool()) {
        // Segment counts crossing the 24-segment gate (23..27).
        const size_t n_segments = fdp.ConsumeIntegralInRange<size_t>(23, 27);
        const std::string segment = token();
        for (size_t s = 0; s < n_segments; s++) {
          input += "/";
          input += segment;
        }
      } else {
        // Lengths crossing the 4096-byte gate (4080..4110).
        const size_t target = fdp.ConsumeIntegralInRange<size_t>(4080, 4110);
        input = "/" + patterns[fdp.ConsumeIntegralInRange<size_t>(
                          0, patterns.size() - 1)];
        while (input.size() < target) {
          input += "/";
          input += token();
        }
        input.resize(target);
      }
    } else if (strategy == 7) {
      // Raw input bytes (match() accepts arbitrary bytes).
      input = fdp.ConsumeRandomLengthString(64);
    } else {
      // Instantiate a derived route (regexp routes: their literal prefix),
      // then mutate.
      const reference_route& base =
          reference[fdp.ConsumeIntegralInRange<size_t>(0,
                                                       reference.size() - 1)];
      if (base.info.segments.empty()) {
        input = "/" + to_ascii(fdp.ConsumeRandomLengthString(40));
      } else {
        for (const compiler::route_segment& segment : base.info.segments) {
          if (segment.kind == compiler::segment_kind::literal) {
            input += "/" + segment.text;
          } else if (segment.kind == compiler::segment_kind::param) {
            input += "/" + token();
          } else {
            const size_t tail = fdp.ConsumeIntegralInRange<size_t>(0, 3);
            for (size_t t = 0; t < tail; t++) {
              input += "/" + token();
            }
            if (tail == 0) {
              input += "/";
            }
          }
        }
      }
      switch (fdp.ConsumeIntegralInRange<int>(0, 6)) {
        case 0:
          if (!input.empty()) {
            input[fdp.ConsumeIntegralInRange<size_t>(0, input.size() - 1)] =
                static_cast<char>('a' + fdp.ConsumeIntegralInRange<int>(0, 25));
          }
          break;
        case 1:
          input += '/';
          break;
        case 2:
          input.insert(fdp.ConsumeIntegralInRange<size_t>(0, input.size()),
                       "/");
          break;
        case 3:
          input += "/" + token();
          break;
        case 4:
          if (const size_t slash = input.find_last_of('/');
              slash != std::string::npos && slash > 0) {
            input.resize(slash);
          }
          break;
        case 5:
          // Flip the case of one byte (matters under ignore_case).
          if (!input.empty()) {
            char& c =
                input[fdp.ConsumeIntegralInRange<size_t>(0, input.size() - 1)];
            c = static_cast<char>(static_cast<unsigned char>(c) ^ 0x20);
          }
          break;
        default:
          break;
      }
    }
    if (has_regexp_route && input.size() > 64) {
      // Keep std::regex inputs short, as fuzz/url_pattern.cc does, to avoid
      // catastrophic backtracking timeouts unrelated to url_pattern_list.
      input.resize(64);
    }
    check_agreement(list, reference, patterns, input);
  }
  return 0;
}
