#ifndef ADA_HELPERS_H
#define ADA_HELPERS_H

#include "ada.h"
#include "common_defs.h"

#include <string_view>
#include <vector>

namespace ada::helpers {

  std::vector<std::string_view> split_string_view(std::string_view input, char delimiter, bool skip_empty = true);
  ada_really_inline uint64_t string_to_uint64(std::string_view view);
  // return 256^x, might overflow. Valid inputs are 0,1,...,7.
  constexpr uint64_t pow256(uint64_t x) { return uint64_t(1) << (8*x); }

} // namespace ada::helpers

#endif // ADA_HELPERS_H
