/**
 * @file url_pattern_list-inl.h
 * @brief Definitions for the url_pattern_list template functions.
 */
#ifndef ADA_URL_PATTERN_LIST_INL_H
#define ADA_URL_PATTERN_LIST_INL_H

#include "ada/common_defs.h"
#include "ada/url_pattern_list.h"
#include "ada/url_pattern-inl.h"
#include "ada/url_pattern_helpers.h"
#include "ada/url_pattern_helpers-inl.h"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if ADA_INCLUDE_URL_PATTERN
namespace ada {

template <url_pattern_regex::regex_concept regex_provider>
tl::expected<url_pattern_list<regex_provider>, errors>
url_pattern_list<regex_provider>::create(
    const std::vector<std::string_view>& pathname_patterns) {
  namespace helpers = url_pattern_list_helpers;
  url_pattern_list list{};
  list.patterns_.reserve(pathname_patterns.size());
  list.routes_.reserve(pathname_patterns.size());
  for (const std::string_view pattern : pathname_patterns) {
    list.patterns_.emplace_back(pattern);
  }
  for (size_t i = 0; i < list.patterns_.size(); i++) {
    // The pattern side goes through ada's own URLPattern machinery: the
    // pattern parser tokenizes and canonicalizes exactly as a URLPattern
    // pathname component would.
    auto options = url_pattern_compile_component_options::PATHNAME;
    auto part_list = url_pattern_helpers::parse_pattern_string(
        list.patterns_[i], options, url_pattern_helpers::canonicalize_pathname);
    if (!part_list) {
      return tl::unexpected(part_list.error());
    }
    helpers::route_info route{};
    if (helpers::classify_parts(*part_list, route.segments,
                                route.group_names)) {
      helpers::finalize_route(route);
    } else {
      // The pattern needs URLPattern regexp semantics: compile it as a
      // pathname component through the provider; it participates in the
      // priority order via its approximated kind sequence.
      auto compile_options = url_pattern_compile_component_options::PATHNAME;
      auto component = url_pattern_component<regex_provider>::compile(
          list.patterns_[i], url_pattern_helpers::canonicalize_pathname,
          compile_options);
      if (!component) {
        return tl::unexpected(component.error());
      }
      route.segments.clear();
      route.group_names = component->group_name_list;
      helpers::approximate_kind_sequence(*part_list, route);
      route.regexp_component =
          static_cast<int32_t>(list.regexp_components_.size());
      list.regexp_components_.push_back(std::move(*component));
    }
    list.routes_.push_back(std::move(route));
  }
  list.compiled_ = helpers::compile_route_set(list.routes_);
  for (size_t i = 0; i < list.routes_.size(); i++) {
    const helpers::route_info& route = list.routes_[i];
    if (route.mode == helpers::route_mode::regexp ||
        (route.mode == helpers::route_mode::sequential &&
         !route.covered_by_static_table)) {
      list.auxiliary_routes_.push_back(static_cast<uint32_t>(i));
    }
  }
  return list;
}

template <url_pattern_regex::regex_concept regex_provider>
void url_pattern_list<regex_provider>::consider_route(
    uint32_t route_index, std::string_view pathname,
    url_pattern_list_helpers::engine_result& best) const {
  namespace helpers = url_pattern_list_helpers;
  const helpers::route_info& candidate = routes_[route_index];
  // Only test candidates that would outrank the current best.
  if (best.route >= 0 &&
      !helpers::route_outranks(candidate, route_index,
                               routes_[static_cast<size_t>(best.route)],
                               static_cast<size_t>(best.route))) {
    return;
  }
  if (candidate.mode == helpers::route_mode::regexp) {
    const url_pattern_component<regex_provider>& component =
        regexp_components_[static_cast<size_t>(candidate.regexp_component)];
    if (component.fast_test(pathname)) {
      // Capture slices are not recoverable through the provider interface;
      // see url_pattern_list_match_result.
      best = helpers::engine_result{};
      best.route = static_cast<int32_t>(route_index);
    }
  } else {
    helpers::engine_result scratch{};
    if (helpers::match_route_sequential(candidate, pathname, scratch)) {
      scratch.route = static_cast<int32_t>(route_index);
      best = scratch;
    }
  }
}

template <url_pattern_regex::regex_concept regex_provider>
url_pattern_list_match_result url_pattern_list<regex_provider>::match(
    std::string_view pathname) const {
  namespace helpers = url_pattern_list_helpers;
  helpers::engine_result best = helpers::match_compiled(compiled_, pathname);
  if (!best.within_fast_path) {
    // The input exceeds a fast-path limit (length, segment count, or no
    // leading '/'): the sequential fallback matches every route with
    // identical priority semantics.
    return match_sequential(pathname);
  }
  // Routes the compiled tables cannot answer for still participate in the
  // priority order: the winner is decided by (kind sequence, insertion
  // index), never by which path matched it.
  for (const uint32_t route_index : auxiliary_routes_) {
    consider_route(route_index, pathname, best);
  }
  url_pattern_list_match_result result{};
  result.route_index = best.route;
  if (best.route >= 0) {
    result.capture_count = best.capture_count;
    result.captures_truncated = best.captures_truncated;
    result.captures = best.captures;
  }
  return result;
}

template <url_pattern_regex::regex_concept regex_provider>
url_pattern_list_match_result
url_pattern_list<regex_provider>::match_sequential(
    std::string_view pathname) const {
  namespace helpers = url_pattern_list_helpers;
  helpers::engine_result best{};
  for (size_t i = 0; i < routes_.size(); i++) {
    consider_route(static_cast<uint32_t>(i), pathname, best);
  }
  url_pattern_list_match_result result{};
  result.route_index = best.route;
  if (best.route >= 0) {
    result.capture_count = best.capture_count;
    result.captures_truncated = best.captures_truncated;
    result.captures = best.captures;
  }
  return result;
}

}  // namespace ada
#endif  // ADA_INCLUDE_URL_PATTERN
#endif  // ADA_URL_PATTERN_LIST_INL_H
