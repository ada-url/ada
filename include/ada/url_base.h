/**
 * @file url_base.h
 * @brief Declaration for the basic URL definitions
 */
#ifndef ADA_URL_BASE_H
#define ADA_URL_BASE_H

#include "ada/common_defs.h"
#include "ada/url_components.h"

#include <string_view>

namespace ada {

  /**
   * @private
   */
  struct url_base {

    virtual ~url_base() = default;

    /**
     * Used for returning the validity from the result of the URL parser.
     */
    bool is_valid{true};

    bool set_username(const std::string_view input);
    bool set_password(const std::string_view input);
    bool set_href(const std::string_view input);

    /** @see https://url.spec.whatwg.org/#dom-url-hash */
    void set_hash(const std::string_view input);

    bool set_port(const std::string_view input);
    void set_search(const std::string_view input);
    bool set_pathname(const std::string_view input);
    bool set_host(const std::string_view input);
    bool set_hostname(const std::string_view input);
    bool set_protocol(const std::string_view input);

    [[nodiscard]] ada_really_inline ada::url_components get_components() noexcept;

    [[nodiscard]] std::string get_origin() const noexcept;
    [[nodiscard]] std::string get_username() const noexcept;
    [[nodiscard]] std::string get_password() const noexcept;
    [[nodiscard]] std::string get_port() const noexcept;
    [[nodiscard]] std::string get_hash() const noexcept;
    [[nodiscard]] std::string get_host() const noexcept;
    [[nodiscard]] std::string get_hostname() const noexcept;
    [[nodiscard]] std::string get_pathname() const noexcept;
    [[nodiscard]] std::string get_search() const noexcept;

    /**
     * @private
     *
     * This function takes already processed input. No need to process it again.
     * Just use this to update the internal state of the class inhering the base.
     *
     * For example;
     * - ada::url should update 'std::optional<std::string> fragment'
     * - ada::url_aggregator should update 'components.hash_start'
     *
     * @param input
     */
    void update_base_fragment(std::optional<std::string> input);

  };

} // namespace ada

#endif
