#ifndef ADA_HELPERS_H
#define ADA_HELPERS_H

#include "ada.h"
#include "common_defs.h"

#include <string_view>
#include <optional>

namespace ada::helpers {

  // return 256^x, might overflow. Valid inputs are 0,1,...,7.
  constexpr uint64_t pow256(uint64_t x) { return uint64_t(1) << (8*x); }
  ada_really_inline std::optional<std::string_view> prune_fragment(std::string_view& input) noexcept;
  std::optional<uint16_t> get_port_fast(std::string_view::iterator begin, std::string_view::iterator end) noexcept;
} // namespace ada::helpers

#endif // ADA_HELPERS_H
