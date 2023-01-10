#ifndef ADA_HELPERS_H
#define ADA_HELPERS_H

#include "ada.h"
#include "common_defs.h"

#include <string_view>
#include <vector>
#include <optional>

namespace ada::helpers {

  std::vector<std::string> split_string_view(std::string_view input, char delimiter, bool skip_empty = true);
  ada_really_inline uint64_t string_to_uint64(std::string_view view);
  ada_really_inline std::optional<std::string_view> prune_fragment(std::string_view& input) noexcept;
} // namespace ada::helpers

#endif // ADA_HELPERS_H
