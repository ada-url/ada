#ifndef ADA_HELPERS_H
#define ADA_HELPERS_H

#include <string_view>
#include <vector>

namespace ada::helpers {

  std::vector<std::string_view> split_string_view(std::string_view input, std::string_view delimiter);

} // namespace ada::helpers

#endif //ADA_HELPERS_H
