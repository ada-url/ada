/**
 * @file url-components.h
 * @brief Declaration for the URL Components
 */
#ifndef ADA_URL_COMPONENTS_H
#define ADA_URL_COMPONENTS_H

#include "ada/common_defs.h"

#include <optional>
#include <string_view>

namespace ada {

  struct url_components {

    url_components() = default;
    url_components(const url_components &u) = default;
    url_components(url_components &&u) noexcept = default;
    url_components &operator=(url_components &&u) noexcept = default;
    url_components &operator=(const url_components &u) = default;
    ADA_ATTRIBUTE_NOINLINE ~url_components() = default;

    size_t protocol_end{0};
    size_t username_end{0};
    size_t host_start{0};
    size_t host_end{0};
    std::optional<uint32_t> port{};
    size_t pathname_start{0};
    std::optional<size_t> search_start{};
    std::optional<size_t> hash_start{};

  }; // struct url_components

} // namespace ada
#endif