/**
 * @file url_aggregator.h
 * @brief Declaration for the basic URL definitions
 */
#ifndef ADA_URL_AGGREGATOR_H
#define ADA_URL_AGGREGATOR_H

#include "ada/common_defs.h"
#include "ada/url_base.h"
#include "ada/url_components.h"

#include <string>
#include <string_view>

namespace ada {

  struct url_aggregator: url_base {

    std::string buffer{};

    url_components components;

    bool set_href(const std::string_view input);
    bool set_host(const std::string_view input);
    bool set_hostname(const std::string_view input);
    bool set_protocol(const std::string_view input);

    [[nodiscard]] ada_really_inline ada::url_components get_components() noexcept;

    [[nodiscard]] std::string get_origin() const noexcept;
    [[nodiscard]] std::string get_href() const noexcept;
    [[nodiscard]] std::string get_username() const noexcept;
    [[nodiscard]] std::string get_password() const noexcept;
    [[nodiscard]] std::string get_port() const noexcept;
    [[nodiscard]] std::string get_hash() const noexcept;
    [[nodiscard]] std::string get_host() const noexcept;
    [[nodiscard]] std::string get_hostname() const noexcept;
    [[nodiscard]] std::string get_pathname() const noexcept;
    [[nodiscard]] std::string get_search() const noexcept;
    [[nodiscard]] std::string get_protocol() const noexcept;

    [[nodiscard]] ada_really_inline bool includes_credentials() const noexcept;
    [[nodiscard]] inline bool cannot_have_credentials_or_port() const;

    /** @private */
    void update_base_hash(std::optional<std::string> input);
    /** @private */
    void update_base_search(std::optional<std::string> input);
    /** @private */
    void update_base_pathname(const std::string_view input);
    /** @private */
    void update_base_username(const std::string_view input);
    /** @private */
    void update_base_password(const std::string_view input);
    /** @private */
    void update_base_port(std::optional<uint32_t> input);
    /** @private */
    bool base_hostname_has_value() const;
    /** @private */
    bool base_fragment_has_value() const;
    /** @private */
    bool base_search_has_value() const;
    /** @private */
    bool base_port_has_value() const;

  }; // url_aggregator

} // namespace ada

#endif
