/**
 * @file ip_address-inl.h
 * @brief Inline hot paths for pure-decimal IPv4 parsing (internal).
 */
#ifndef ADA_IP_ADDRESS_INL_H
#define ADA_IP_ADDRESS_INL_H

#include "ada/ip_address.h"
#include "ada/checkers.h"

#include <cstdint>

namespace ada::ip_address {

/**
 * Fast pure-decimal IPv4 parse. Returns packed address or ipv4_fast_fail.
 * Accepts an optional single trailing dot.
 *
 * Unrolled 1-3 digit per-octet parse with length early-out. This is the
 * common-case host path for addresses like "192.168.1.1".
 */
ada_really_inline uint64_t
try_parse_ipv4_fast(std::string_view input) noexcept {
  const size_t len = input.size();
  // Shortest pure decimal: "0.0.0.0" (7). Longest + trailing dot: 16.
  if (len < 7 || len > 16) [[unlikely]] {
    return checkers::ipv4_fast_fail;
  }

  const char* p = input.data();
  const char* const pend = p + len;
  uint32_t ipv4 = 0;

  for (int i = 0; i < 4; ++i) {
    if (p == pend) [[unlikely]] {
      return checkers::ipv4_fast_fail;
    }
    uint32_t val;
    char c = *p;
    if (c >= '0' && c <= '9') [[likely]] {
      val = static_cast<uint32_t>(c - '0');
      ++p;
    } else {
      return checkers::ipv4_fast_fail;
    }
    if (p < pend) {
      c = *p;
      if (c >= '0' && c <= '9') {
        if (val == 0) [[unlikely]] {
          return checkers::ipv4_fast_fail;
        }
        val = val * 10u + static_cast<uint32_t>(c - '0');
        ++p;
        if (p < pend) {
          c = *p;
          if (c >= '0' && c <= '9') {
            val = val * 10u + static_cast<uint32_t>(c - '0');
            ++p;
            if (val > 255u) [[unlikely]] {
              return checkers::ipv4_fast_fail;
            }
          }
        }
      }
    }
    ipv4 = (ipv4 << 8) | val;
    if (i < 3) {
      if (p == pend || *p != '.') [[unlikely]] {
        return checkers::ipv4_fast_fail;
      }
      ++p;
    }
  }
  if (p != pend) {
    if (p == pend - 1 && *p == '.') {
      return ipv4;
    }
    return checkers::ipv4_fast_fail;
  }
  return ipv4;
}

}  // namespace ada::ip_address

#endif  // ADA_IP_ADDRESS_INL_H
