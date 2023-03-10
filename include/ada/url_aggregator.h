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

    url_aggregator() = default;
    url_aggregator(const url_aggregator &u) = default;
    url_aggregator(url_aggregator &&u) noexcept = default;
    url_aggregator &operator=(url_aggregator &&u) noexcept = default;
    url_aggregator &operator=(const url_aggregator &u) = default;
    ~url_aggregator() = default;

    std::string buffer{};

    url_components components{};

    bool set_href(const std::string_view input);
    bool set_host(const std::string_view input);
    bool set_hostname(const std::string_view input);
    inline void set_scheme(std::string_view new_scheme) noexcept;

    inline void copy_scheme(const url_aggregator& u) noexcept;

    [[nodiscard]] std::string get_origin() const noexcept;
    [[nodiscard]] const std::string& get_href() const noexcept;
    [[nodiscard]] std::string_view get_username() const noexcept;
    [[nodiscard]] std::string_view get_password() const noexcept;
    [[nodiscard]] std::string_view get_port() const noexcept;
    [[nodiscard]] std::string_view get_hash() const noexcept;
    [[nodiscard]] std::string_view get_host() const noexcept;
    [[nodiscard]] std::string_view get_hostname() const noexcept;
    [[nodiscard]] std::string_view get_pathname() const noexcept;
    [[nodiscard]] std::string_view get_search() const noexcept;
    [[nodiscard]] std::string_view get_protocol() const noexcept;

    [[nodiscard]] ada_really_inline bool includes_credentials() const noexcept;
    [[nodiscard]] inline bool cannot_have_credentials_or_port() const;

    /** @private */
    inline void update_base_hash(std::string_view input);
    /** @private */
    inline void update_base_search(std::optional<std::string_view> input);
    /** @private */
    inline void update_base_pathname(const std::string_view input);
    /** @private */
    inline void update_base_username(const std::string_view input);
    /** @private */
    inline void update_base_password(const std::string_view input);
    /** @private */
    inline void update_base_port(std::optional<uint16_t> input);
    /** @private */
    inline std::optional<uint16_t> retrieve_base_port() const;
    /** @private */
    inline std::string_view retrieve_base_pathname() const;
    /** @private */
    inline void clear_base_hash();
    /** @private */
    inline bool base_hostname_has_value() const;
    /** @private */
    inline bool base_fragment_has_value() const;
    /** @private */
    inline bool base_search_has_value() const;
    /** @private */
    inline bool base_port_has_value() const;
    /** @private */
    template <bool has_state_override = false>
    [[nodiscard]] ada_really_inline bool parse_scheme(const std::string_view input);

    /**
     * Useful for implementing efficient serialization for the URL.
     *
     * https://user@pass:example.com:1234/foo/bar?baz#quux
     *      |      |    |          | ^^^^|       |   |
     *      |      |    |          | |   |       |   `----- hash_start
     *      |      |    |          | |   |       `--------- search_start
     *      |      |    |          | |   `----------------- pathname_start
     *      |      |    |          | `--------------------- port
     *      |      |    |          `----------------------- host_end
     *      |      |    `---------------------------------- host_start
     *      |      `--------------------------------------- username_end
     *      `---------------------------------------------- protocol_end
     *
     * Inspired after servo/url
     * @see https://github.com/servo/rust-url/blob/b65a45515c10713f6d212e6726719a020203cc98/url/src/quirks.rs#L31
     */
    [[nodiscard]] ada_really_inline const ada::url_components& get_components() const noexcept;
    std::string to_string() const;

  }; // url_aggregator

} // namespace ada

#endif
