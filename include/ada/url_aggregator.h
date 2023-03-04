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

  struct url_aggregator: virtual url_base{

    std::string buffer{};

    url_components components;

    /**
     * @return Returns true on successful operation.
     * @see https://url.spec.whatwg.org/#dom-url-username
     */
    bool set_username(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-password
     */
    bool set_password(const std::string_view input);

    /**
     * @see https://url.spec.whatwg.org/#dom-url-href
     */
    bool set_href(const std::string_view input);

    /**
     * @see https://url.spec.whatwg.org/#dom-url-hash
     */
    void set_hash(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-port
     */
    bool set_port(const std::string_view input);

    /**
     * This function always succeeds.
     * @see https://url.spec.whatwg.org/#dom-url-search
     */
    void set_search(const std::string_view input);

    /**
    * @return Returns true on success.
    * @see https://url.spec.whatwg.org/#dom-url-search
    */
    bool set_pathname(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-host
     */
    bool set_host(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-hostname
     */
    bool set_hostname(const std::string_view input);

    /**
     * @return Returns true on success.
     * @see https://url.spec.whatwg.org/#dom-url-protocol
     */
    bool set_protocol(const std::string_view input);

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
    [[nodiscard]] ada_really_inline ada::url_components get_components() noexcept;

    /**
     * The origin getter steps are to return the serialization of this’s URL’s origin. [HTML]
     * @see https://url.spec.whatwg.org/#concept-url-origin
     */
    [[nodiscard]] std::string get_origin() const noexcept;

    /**
     * The password getter steps are to return this’s URL’s password.
     * @see https://url.spec.whatwg.org/#dom-url-password
     */
    [[nodiscard]] std::string get_password() const noexcept;

    /**
     * Return this’s URL’s port, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-port
     */
    [[nodiscard]] std::string get_port() const noexcept;

    /**
     * Return U+0023 (#), followed by this’s URL’s fragment.
     * @see https://url.spec.whatwg.org/#dom-url-hash
     */
    [[nodiscard]] std::string get_hash() const noexcept;

    /**
     * Return url’s host, serialized, followed by U+003A (:) and url’s port, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-host
     */
    [[nodiscard]] std::string get_host() const noexcept;

    /**
     * Return this’s URL’s host, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-hostname
     */
    [[nodiscard]] std::string get_hostname() const noexcept;

    /**
     * The pathname getter steps are to return the result of URL path serializing this’s URL.
     * @see https://url.spec.whatwg.org/#dom-url-pathname
     */
    [[nodiscard]] std::string get_pathname() const noexcept;

    /**
     * Return U+003F (?), followed by this’s URL’s query.
     * @see https://url.spec.whatwg.org/#dom-url-search
     */
    [[nodiscard]] std::string get_search() const noexcept;

  };

} // namespace ada

#endif
