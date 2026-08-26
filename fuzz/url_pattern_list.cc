#include <fuzzer/FuzzedDataProvider.h>

#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

#include "ada.cpp"
#include "ada.h"

using regex_provider = ada::url_pattern_regex::std_regex_provider;
using list_type = ada::url_pattern_list<regex_provider>;
namespace helpers = ada::url_pattern_list_helpers;

// One route of the independent reference: either the sequential segment
// matcher's route_info (built through the same public helper entry points
// url_pattern_list::create uses) or, for patterns outside the safe subset,
// the compiled URLPattern pathname component.
struct reference_route {
  helpers::route_info info{};
  std::optional<ada::url_pattern_component<regex_provider>> component{};
};

// Mirrors the classification url_pattern_list::create performs. Returns
// false when a pattern is rejected, in which case create must fail too.
static bool build_reference(const std::vector<std::string>& patterns,
                            std::vector<reference_route>& out) {
  for (const std::string& pattern : patterns) {
    auto options = ada::url_pattern_compile_component_options::PATHNAME;
    auto part_list = ada::url_pattern_helpers::parse_pattern_string(
        pattern, options, ada::url_pattern_helpers::canonicalize_pathname);
    if (!part_list) {
      return false;
    }
    reference_route route{};
    if (helpers::classify_parts(*part_list, route.info.segments,
                                route.info.group_names)) {
      helpers::finalize_route(route.info);
    } else {
      auto component = ada::url_pattern_component<regex_provider>::compile(
          pattern, ada::url_pattern_helpers::canonicalize_pathname, options);
      if (!component) {
        return false;
      }
      helpers::approximate_kind_sequence(*part_list, route.info);
      route.component = std::move(*component);
    }
    out.push_back(std::move(route));
  }
  return true;
}

// The sequential reference oracle: every route is tested with the
// no-fast-path matcher (or the regex provider) and ranked with the same
// priority rule the compiled engine implements. Any disagreement with
// url_pattern_list::match is a bug in the compiled tables.
static int32_t reference_match(const std::vector<reference_route>& routes,
                               std::string_view pathname,
                               helpers::engine_result& best) {
  best = helpers::engine_result{};
  int32_t best_route = -1;
  for (size_t i = 0; i < routes.size(); i++) {
    const reference_route& route = routes[i];
    if (best_route >= 0 &&
        !helpers::route_outranks(route.info, i,
                                 routes[static_cast<size_t>(best_route)].info,
                                 static_cast<size_t>(best_route))) {
      continue;
    }
    if (route.component.has_value()) {
      if (route.component->fast_test(pathname)) {
        best = helpers::engine_result{};
        best_route = static_cast<int32_t>(i);
      }
    } else {
      helpers::engine_result scratch{};
      if (helpers::match_route_sequential(route.info, pathname, scratch)) {
        best = scratch;
        best_route = static_cast<int32_t>(i);
      }
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
  sink += result.has_match() ? 1 : 0;
  for (const auto& capture : result.captures) {
    sink += capture.offset;
    sink += capture.length;
  }
  (void)sink;
}

static void check_agreement(const list_type& list,
                            const std::vector<reference_route>& reference,
                            const std::vector<std::string>& patterns,
                            const std::string& input) {
  const auto matched = list.match(input);
  exercise_match_result(matched);
  helpers::engine_result expected{};
  const int32_t expected_route = reference_match(reference, input, expected);
  if (matched.route_index != expected_route) {
    printf("url_pattern_list winner mismatch on input '%s': list=%d ref=%d\n",
           input.c_str(), matched.route_index, expected_route);
    for (const std::string& pattern : patterns) {
      printf("  pattern: '%s'\n", pattern.c_str());
    }
    abort();
  }
  if (expected_route < 0 ||
      reference[static_cast<size_t>(expected_route)].component.has_value()) {
    // Regexp-mode winners report no capture slices; nothing more to compare.
    return;
  }
  const bool captures_agree =
      matched.capture_count == expected.capture_count &&
      matched.captures_truncated == expected.captures_truncated;
  bool slices_agree = captures_agree;
  for (uint32_t k = 0; slices_agree && k < matched.capture_count; k++) {
    slices_agree = matched.captures[k].offset == expected.captures[k].offset &&
                   matched.captures[k].length == expected.captures[k].length;
  }
  if (!slices_agree) {
    printf("url_pattern_list capture mismatch on input '%s' (route %d)\n",
           input.c_str(), expected_route);
    abort();
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
  // often and derived inputs need no canonicalization.
  auto token = [&fdp]() -> std::string {
    static constexpr char alphabet[] =
        "abcdefghijklmnopqrstuvwxyz0123456789-_.~";
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
    const int mode = fdp.ConsumeIntegralInRange<int>(0, 5);
    if (mode == 0) {
      // Raw pattern bytes: URLPattern syntax errors are expected and must
      // surface as a clean create() error, never as a crash.
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
        const int kind = fdp.ConsumeIntegralInRange<int>(0, 9);
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
        } else {
          pattern += "/" + token();
        }
      }
      patterns.push_back(std::move(pattern));
    }
  }
  std::vector<std::string_view> views(patterns.begin(), patterns.end());
  auto list_result = list_type::create(views);

  // --- strategy (ii): the independent reference must agree on
  // constructibility, on every winner, and on every capture slice ----------
  std::vector<reference_route> reference;
  const bool reference_ok = build_reference(patterns, reference);
  if (list_result.has_value() != reference_ok) {
    printf("create()/reference disagreement: create=%d reference=%d\n",
           list_result.has_value() ? 1 : 0, reference_ok ? 1 : 0);
    abort();
  }
  if (!list_result) {
    return 0;
  }
  const list_type& list = *list_result;

  // Exercise the full public surface.
  volatile uint64_t sink = list.size();
  bool has_regexp_route = false;
  for (size_t i = 0; i < list.size(); i++) {
    sink += list.pattern(i).size();
    for (const std::string& name : list.group_names(i)) {
      sink += name.size();
    }
    has_regexp_route |= reference[i].component.has_value();
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
      // Instantiate a derived route, then mutate.
      const reference_route& base =
          reference[fdp.ConsumeIntegralInRange<size_t>(0,
                                                       reference.size() - 1)];
      if (base.info.segments.empty()) {
        input = "/" + to_ascii(fdp.ConsumeRandomLengthString(40));
      } else {
        for (const helpers::route_segment& segment : base.info.segments) {
          if (segment.kind == helpers::segment_kind::literal) {
            input += "/" + segment.text;
          } else if (segment.kind == helpers::segment_kind::param) {
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
      switch (fdp.ConsumeIntegralInRange<int>(0, 5)) {
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
