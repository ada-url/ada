#ifndef ADA_HELPERS_H
#define ADA_HELPERS_H

#include "common_defs.h"
#include "url.h"
#include "state.h"

#include <string_view>
#include <optional>

namespace ada::helpers {

  ada_really_inline std::optional<std::string_view> prune_fragment(std::string_view& input) noexcept;
  ada_really_inline void shorten_path(ada::url &url) noexcept;
  ada_really_inline void remove_ascii_tab_or_newline(std::string& input) noexcept;
} // namespace ada::helpers

#endif // ADA_HELPERS_H
