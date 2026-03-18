/**
 * @file scheme-inl.h
 * @brief Definitions for the URL scheme.
 */
#ifndef ADA_SCHEME_INL_H
#define ADA_SCHEME_INL_H

#include "ada/scheme.h"

namespace ada::scheme {

/**
 * @namespace ada::scheme::details
 * @brief Includes the definitions for scheme specific entities
 */
namespace details {
// for use with is_special and get_special_port
// Spaces, if present, are removed from URL.
constexpr std::string_view is_special_list[] = {"http", " ",   "https", "ws",
                                                "ftp",  "wss", "file",  " "};
// for use with get_special_port
constexpr uint16_t special_ports[] = {80, 0, 443, 80, 21, 443, 0, 0};

// @private
// convert a string_view to a 64-bit integer key for fast comparison
constexpr uint64_t make_key(std::string_view sv) {
  uint64_t val = 0;
  for (size_t i = 0; i < sv.size(); i++)
    val |= (uint64_t)(uint8_t)sv[i] << (i * 8);
  return val;
}
// precomputed keys for the special schemes, indexed by a hash of the input
// string
constexpr uint64_t scheme_keys[] = {
    make_key("http"),   // 0: HTTP
    0,                  // 1: sentinel
    make_key("https"),  // 2: HTTPS
    make_key("ws"),     // 3: WS
    make_key("ftp"),    // 4: FTP
    make_key("wss"),    // 5: WSS
    make_key("file"),   // 6: FILE
    0,                  // 7: sentinel
};

// @private
// branchless load of up to 5 characters into a uint64_t, padding with zeros if
// n < 5
inline uint64_t branchless_load5(const char *p, size_t n) {
  uint64_t input = (uint8_t)p[0];
  input |= ((uint64_t)(uint8_t)p[n > 1] << 8) & (0 - (uint64_t)(n > 1));
  input |= ((uint64_t)(uint8_t)p[(n > 2) * 2] << 16) & (0 - (uint64_t)(n > 2));
  input |= ((uint64_t)(uint8_t)p[(n > 3) * 3] << 24) & (0 - (uint64_t)(n > 3));
  input |= ((uint64_t)(uint8_t)p[(n > 4) * 4] << 32) & (0 - (uint64_t)(n > 4));
  return input;
}
}  // namespace details

/****
 * @private
 * In is_special, get_scheme_type, and get_special_port, we
 * use a standard hashing technique to find the index of the scheme in
 * the is_special_list. The hashing technique is based on the size of
 * the scheme and the first character of the scheme. It ensures that we
 * do at most one string comparison per call. If the protocol is
 * predictible (e.g., it is always "http"), we can get a better average
 * performance by using a simpler approach where we loop and compare
 * scheme with all possible protocols starting with the most likely
 * protocol. Doing multiple comparisons may have a poor worst case
 * performance, however. In this instance, we choose a potentially
 * slightly lower best-case performance for a better worst-case
 * performance. We can revisit this choice at any time.
 *
 * Reference:
 * Schmidt, Douglas C. "Gperf: A perfect hash function generator."
 * More C++ gems 17 (2000).
 *
 * Reference: https://en.wikipedia.org/wiki/Perfect_hash_function
 *
 * Reference: https://github.com/ada-url/ada/issues/617
 ****/

ada_really_inline constexpr bool is_special(std::string_view scheme) {
  if (scheme.empty()) {
    return false;
  }
  int hash_value = (2 * scheme.size() + (unsigned)(scheme[0])) & 7;
  const std::string_view target = details::is_special_list[hash_value];
  return (target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1));
}
constexpr uint16_t get_special_port(std::string_view scheme) noexcept {
  if (scheme.empty()) {
    return 0;
  }
  int hash_value = (2 * scheme.size() + (unsigned)(scheme[0])) & 7;
  const std::string_view target = details::is_special_list[hash_value];
  if (scheme.size() == target.size() &&
      details::branchless_load5(scheme.data(), scheme.size()) ==
          details::scheme_keys[hash_value]) {
    return details::special_ports[hash_value];
  } else {
    return 0;
  }
}
constexpr uint16_t get_special_port(ada::scheme::type type) noexcept {
  return details::special_ports[int(type)];
}
constexpr ada::scheme::type get_scheme_type(std::string_view scheme) noexcept {
  if (scheme.empty()) {
    return ada::scheme::NOT_SPECIAL;
  }
  int hash_value = (2 * scheme.size() + (unsigned)(scheme[0])) & 7;
  const std::string_view target = details::is_special_list[hash_value];
  if (scheme.size() == target.size() &&
      details::branchless_load5(scheme.data(), scheme.size()) ==
          details::scheme_keys[hash_value]) {
    return ada::scheme::type(hash_value);
  } else {
    return ada::scheme::NOT_SPECIAL;
  }
}

}  // namespace ada::scheme

#endif  // ADA_SCHEME_INL_H
