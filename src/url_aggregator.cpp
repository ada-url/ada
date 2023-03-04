#include "ada.h"
#include "ada/url_components.h"
#include "ada/url_aggregator.h"

namespace ada {

  void url_aggregator::set_hash(const std::string_view input) {
    if (components.hash_start != ada::url_components::omitted) {
      // TODO: process input in here.
      buffer = buffer.substr(0, components.hash_start) + std::string(input);
    } else {
      // TODO: Update hash_start and buffer
    }
  }

  [[nodiscard]] ada_really_inline ada::url_components url_aggregator::get_components() noexcept {
    return components;
  }

} // namespace ada
