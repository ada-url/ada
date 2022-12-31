#ifndef ADA_HELPERS_H
#define ADA_HELPERS_H

#include "ada.h"
#include "common_defs.h"

#include <string_view>
#include <vector>

namespace ada::helpers {

  std::vector<std::string_view> split_string_view(std::string_view input, std::string_view delimiter);
  ada_really_inline uint64_t string_to_uint64(std::string_view view);
  ada_really_inline uint32_t string_to_uint32(const char *data);

} // namespace ada::helpers

#endif //ADA_HELPERS_H
