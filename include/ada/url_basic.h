/**
 * @file url_basic.h
 * @brief Declaration for the basic URL definitions
 */
#ifndef ADA_URL_BASIC_H
#define ADA_URL_BASIC_H

#include "ada/common_defs.h"
#include "ada/url_components.h"

#include <string_view>

namespace ada {

  struct url_basic {

    virtual ~url_basic() = default;

    void set_hash(const std::string_view input);

    [[nodiscard]] ada_really_inline ada::url_components get_components() noexcept;

  };

} // namespace ada

#endif
