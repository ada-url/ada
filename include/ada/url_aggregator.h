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

  /**
   * @brief Lightweight URL struct.
   *
   * @details The url_aggregator class aims to minimize temporary memory allocation
   * while representing a parsed URL.
   * Internally, it contains a single normalized URL (the href), and it
   * makes available the components, mostly using std::string_view.
   */
  struct url_aggregator: url_base {

    url_aggregator() = default;
    url_aggregator(const url_aggregator &u) = default;
    url_aggregator(url_aggregator &&u) noexcept = default;
    url_aggregator &operator=(url_aggregator &&u) noexcept = default;
    url_aggregator &operator=(const url_aggregator &u) = default;
    ~url_aggregator() = default;

    bool set_href(const std::string_view input);
    bool set_host(const std::string_view input);
    bool set_hostname(const std::string_view input);
    bool set_protocol(const std::string_view input);
    bool set_username(const std::string_view input);
    bool set_password(const std::string_view input);
    bool set_port(const std::string_view input);
    bool set_pathname(const std::string_view input);
    void set_search(const std::string_view input);
    void set_hash(const std::string_view input);
    inline void set_scheme(std::string_view new_scheme) noexcept;
    inline void copy_scheme(const url_aggregator& u) noexcept;

    [[nodiscard]] bool has_valid_domain() const noexcept override;

    /** @private */
    inline bool has_authority() const noexcept;

    /**
     * The origin getter steps are to return the serialization of this’s URL’s
     * origin. [HTML]
     * @return a newly allocated string.
     * @see https://url.spec.whatwg.org/#concept-url-origin
     */
    [[nodiscard]] std::string get_origin() const noexcept override;
    /**
     * Return the normalized string.
     * This function does not allocate memory.
     * It is highly efficient.
     * @return a constant reference to the underlying normalized URL.
     * @see https://url.spec.whatwg.org/#dom-url-href
     * @see https://url.spec.whatwg.org/#concept-url-serializer
     */
    [[nodiscard]] const std::string& get_href() const noexcept;
    /**
     * The username getter steps are to return this’s URL’s username.
     * This function does not allocate memory.
     * @return a lightweight std::string_view.
     * @see https://url.spec.whatwg.org/#dom-url-username
     */
    [[nodiscard]] std::string_view get_username() const noexcept;
    /**
     * The password getter steps are to return this’s URL’s password.
     * This function does not allocate memory.
     * @return a lightweight std::string_view.
     * @see https://url.spec.whatwg.org/#dom-url-password
     */
    [[nodiscard]] std::string_view get_password() const noexcept;
    /**
     * Return this’s URL’s port, serialized.
     * This function does not allocate memory.
     * @return a lightweight std::string_view.
     * @see https://url.spec.whatwg.org/#dom-url-port
     */
    [[nodiscard]] std::string_view get_port() const noexcept;
    /**
     * Return U+0023 (#), followed by this’s URL’s fragment.
     * This function does not allocate memory.
     * @return a lightweight std::string_view..
     * @see https://url.spec.whatwg.org/#dom-url-hash
     */
    [[nodiscard]] std::string_view get_hash() const noexcept;
    /**
     * Return url’s host, serialized, followed by U+003A (:) and url’s port,
     * serialized.
     * This function does not allocate memory.
     * @return a lightweight std::string_view.
     * @see https://url.spec.whatwg.org/#dom-url-host
     */
    [[nodiscard]] std::string_view get_host() const noexcept;
    /**
     * Return this’s URL’s host, serialized.
     * This function does not allocate memory.
     * @return a lightweight std::string_view.
     * @see https://url.spec.whatwg.org/#dom-url-hostname
     */
    [[nodiscard]] std::string_view get_hostname() const noexcept;

    /**
     * The pathname getter steps are to return the result of URL path serializing
     * this’s URL.
     * This function does not allocate memory.
     * @return a lightweight std::string_view.
     * @see https://url.spec.whatwg.org/#dom-url-pathname
     */
    [[nodiscard]] std::string_view get_pathname() const noexcept;
    /**
     * Return U+003F (?), followed by this’s URL’s query.
     * This function does not allocate memory.
     * @return a lightweight std::string_view.
     * @see https://url.spec.whatwg.org/#dom-url-search
     */
    [[nodiscard]] std::string_view get_search() const noexcept;
    /**
     * The protocol getter steps are to return this’s URL’s scheme, followed by
     * U+003A (:).
     * This function does not allocate memory.
     * @return a lightweight std::string_view.
     * @see https://url.spec.whatwg.org/#dom-url-protocol
     */
    [[nodiscard]] std::string_view get_protocol() const noexcept;
    /**
     * A URL includes credentials if its username or password is not the empty
     * string.
     */
    [[nodiscard]] ada_really_inline bool includes_credentials() const noexcept;
    /**
     * @private
     *
     * A URL cannot have a username/password/port if its host is null or the empty
     * string, or its scheme is "file".
     */
    [[nodiscard]] inline bool cannot_have_credentials_or_port() const;

    /** @private */
    template <bool override_hostname = false>
    bool set_host_or_hostname(const std::string_view input);

    /** @private */
    ada_really_inline bool parse_host(std::string_view input);

    /** @private */
    inline void update_unencoded_base_hash(std::string_view input);
    /** @private */
    inline void update_base_hostname(std::string_view input);
    /** @private */
    inline void update_base_search(std::string_view input);
    /** @private */
    inline void update_base_search(std::string_view input, const uint8_t* query_percent_encode_set);
    /** @private */
    inline void update_base_pathname(const std::string_view input);
    /** @private */
    inline void update_base_username(const std::string_view input);
    /** @private */
    inline void append_base_username(const std::string_view input);
    /** @private */
    inline void update_base_password(const std::string_view input);
    /** @private */
    inline void append_base_password(const std::string_view input);
    /** @private */
    inline void update_base_port(std::optional<uint16_t> input) override;
    /** @private */
    inline void append_base_pathname(const std::string_view input);
    /** @private */
    inline std::optional<uint16_t> retrieve_base_port() const;
    /** @private */
    inline std::string_view retrieve_base_pathname() const;
    /** @private */
    inline void clear_base_port();
    /** @private */
    inline void clear_base_hostname() override;
    /** @private */
    inline void clear_base_pathname() override;
    /** @private */
    inline void clear_base_search() override;
    /** @private */
    inline bool base_fragment_has_value() const;
    /** @private */
    inline bool base_search_has_value() const;
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
     *
     * @return a constant reference to the underlying component attribute.
     *
     * @see https://github.com/servo/rust-url/blob/b65a45515c10713f6d212e6726719a020203cc98/url/src/quirks.rs#L31
     */
    [[nodiscard]] ada_really_inline const ada::url_components& get_components() const noexcept;
    /**
     * Returns a string representation of this URL.
     */
    std::string to_string() const override;
    /**
     * Verifies that the parsed URL could be valid. Useful for debugging purposes.
     * @return true if the URL is valid, otherwise return true of the offsets are possible.
     */
    bool validate() const noexcept;

    private:

      /** @private */
      std::string buffer{};

      /** @private */
      url_components components{};

      /**
       * @private
       *
       * Return true on success.
       * @see https://url.spec.whatwg.org/#concept-ipv4-parser
       */
      [[nodiscard]] bool parse_ipv4(std::string_view input);

      /**
       * @private
       *
       * Return true on success.
       * @see https://url.spec.whatwg.org/#concept-ipv6-parser
       */
      [[nodiscard]] bool parse_ipv6(std::string_view input);

      /**
       * @private
       *
       * Return true on success.
       * @see https://url.spec.whatwg.org/#concept-opaque-host-parser
       */
      [[nodiscard]] bool parse_opaque_host(std::string_view input);

      /** @private */
      ada_really_inline void parse_path(std::string_view input);

  }; // url_aggregator

} // namespace ada

#endif
