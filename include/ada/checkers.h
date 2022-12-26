#ifndef ADA_CHECKERS_H
#define ADA_CHECKERS_H

#include <string_view>

namespace ada::checkers {

  bool ends_in_a_number(std::string_view input, bool &has_validation_error);
  bool is_windows_drive_letter(std::string_view input);
  bool is_normalized_windows_drive_letter(std::string_view input);

} // namespace ada::checkers

#endif //ADA_CHECKERS_H
