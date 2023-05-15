#ifndef LINE_ITERATOR_H
#define LINE_ITERATOR_H

#include <string_view>

struct line_iterator {
  std::string_view all_text{};
  size_t next_end_of_line{0};
  line_iterator(const char *_buffer, size_t _len) : all_text(_buffer, _len) {}

  inline bool find_another_complete_line() noexcept {
    next_end_of_line = all_text.find('\n');
    return next_end_of_line != std::string_view::npos;
  }

  inline operator bool() const noexcept {
    return next_end_of_line != std::string_view::npos;
  }

  inline std::string_view grab_line() noexcept {
    auto line = all_text.substr(0, next_end_of_line);  // advance to next EOL
    // remove anything prior to said EOL
    all_text.remove_prefix(next_end_of_line + 1);
    return line;
  }

  inline size_t tail() const noexcept { return all_text.size(); }
};

#endif