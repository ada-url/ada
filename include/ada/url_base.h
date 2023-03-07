/**
 * @file url_base.h
 * @brief Declaration for the basic URL definitions
 */
#ifndef ADA_URL_BASE_H
#define ADA_URL_BASE_H

#include "ada/common_defs.h"
#include "ada/url_components.h"
#include "scheme.h"

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

    /**
     * A URL has an opaque path if its path is a string.
     */
    bool has_opaque_path{false};

    /**
     * @private
     */
    ada::scheme::type type{ada::scheme::type::NOT_SPECIAL};

    /** @see https://url.spec.whatwg.org/#dom-url-username */
    bool set_username(const std::string_view input);
    /** @see https://url.spec.whatwg.org/#dom-url-password */
    bool set_password(const std::string_view input);
    /** @see https://url.spec.whatwg.org/#dom-url-href */
    virtual bool set_href(const std::string_view input) = 0;
    /** @see https://url.spec.whatwg.org/#dom-url-hash */
    void set_hash(const std::string_view input);
    /** @see https://url.spec.whatwg.org/#dom-url-port */
    bool set_port(const std::string_view input);
    /** @see https://url.spec.whatwg.org/#dom-url-search */
    void set_search(const std::string_view input);
    /** @see https://url.spec.whatwg.org/#dom-url-search */
    bool set_pathname(const std::string_view input);
    /** @see https://url.spec.whatwg.org/#dom-url-host */
    virtual bool set_host(const std::string_view input) = 0;
    /** @see https://url.spec.whatwg.org/#dom-url-hostname */
    virtual bool set_hostname(const std::string_view input) = 0;
    /** @see https://url.spec.whatwg.org/#dom-url-protocol */
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
    [[nodiscard]] virtual ada_really_inline ada::url_components get_components() noexcept = 0;

    /**
     * The origin getter steps are to return the serialization of this’s URL’s origin. [HTML]
     * @see https://url.spec.whatwg.org/#concept-url-origin
     */
    [[nodiscard]] virtual std::string get_origin() const noexcept = 0;
    /**
     * @see https://url.spec.whatwg.org/#dom-url-href
     * @see https://url.spec.whatwg.org/#concept-url-serializer
     */
    [[nodiscard]] virtual std::string get_href() const noexcept = 0;
    /** @see https://url.spec.whatwg.org/#dom-url-username */
    [[nodiscard]] virtual std::string get_username() const noexcept = 0;
    /** @see https://url.spec.whatwg.org/#dom-url-password */
    [[nodiscard]] virtual std::string get_password() const noexcept = 0;
    /** @see https://url.spec.whatwg.org/#dom-url-port */
    [[nodiscard]] virtual std::string get_port() const noexcept = 0;
    /**
     * Return U+0023 (#), followed by this’s URL’s fragment.
     * @see https://url.spec.whatwg.org/#dom-url-hash
     */
    [[nodiscard]] virtual std::string get_hash() const noexcept = 0;
    /**
     * Return url’s host, serialized, followed by U+003A (:) and url’s port, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-host
     */
    [[nodiscard]] virtual std::string get_host() const noexcept = 0;
    /**
     * Return this’s URL’s host, serialized.
     * @see https://url.spec.whatwg.org/#dom-url-hostname
     */
    [[nodiscard]] virtual std::string get_hostname() const noexcept = 0;
    /**
     * The pathname getter steps are to return the result of URL path serializing this’s URL.
     * @see https://url.spec.whatwg.org/#dom-url-pathname
     */
    [[nodiscard]] virtual std::string get_pathname() const noexcept = 0;
    /**
     * Return U+003F (?), followed by this’s URL’s query.
     * @see https://url.spec.whatwg.org/#dom-url-search
     */
    [[nodiscard]] virtual std::string get_search() const noexcept = 0;

    /**
     * The protocol getter steps are to return this’s URL’s scheme, followed by U+003A (:).
     * @see https://url.spec.whatwg.org/#dom-url-protocol
     */
    [[nodiscard]] virtual std::string get_protocol() const noexcept = 0;

    /**
     * A URL is special if its scheme is a special scheme. A URL is not special if its scheme is not a special scheme.
     */
    [[nodiscard]] ada_really_inline bool is_special() const noexcept;

    /**
     * @private
     *
     * Return the 'special port' if the URL is special and not 'file'.
     * Returns 0 otherwise.
     */
    [[nodiscard]] inline uint16_t get_special_port() const;

    /**
     * @private
     *
     * Get the default port if the url's scheme has one, returns 0 otherwise.
     */
    [[nodiscard]] ada_really_inline uint16_t scheme_default_port() const noexcept;

    /**
     * A URL includes credentials if its username or password is not the empty string.
     */
    [[nodiscard]] virtual ada_really_inline bool includes_credentials() const noexcept = 0;

    /**
     * @private
     *
     * A URL cannot have a username/password/port if its host is null or the empty string, or its scheme is "file".
     */
    [[nodiscard]] virtual inline bool cannot_have_credentials_or_port() const = 0;

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
    virtual void update_base_hash(std::optional<std::string> input) = 0;
    /** @private */
    virtual void update_base_search(std::optional<std::string> input) = 0;
    /** @private */
    virtual void update_base_pathname(const std::string_view input) = 0;
    /** @private */
    virtual void update_base_username(const std::string_view input) = 0;
    /** @private */
    virtual void update_base_password(const std::string_view input) = 0;
    /** @private */
    virtual void update_base_port(std::optional<uint32_t> input) = 0;
    /** @private */
    virtual std::optional<uint32_t> retrieve_base_port() = 0;
    /** @private */
    virtual bool base_hostname_has_value() const = 0;
    /** @private */
    virtual bool base_fragment_has_value() const = 0;
    /** @private */
    virtual bool base_search_has_value() const = 0;
    /** @private */
    virtual bool base_port_has_value() const = 0;


    private:
      /**
       * @private
       *
       * Parse the path from the provided input.
       * Return true on success. Control characters not trimmed from the ends (they should have
       * been removed if needed). The input is expected to be UTF-8.
       *
       * @see https://url.spec.whatwg.org/
       */
      ada_really_inline bool parse_path(std::string_view input);

  }; // url_base

} // namespace ada

#endif
