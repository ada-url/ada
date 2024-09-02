/**
 * @file url_search_params.h
 * @brief Declaration for the URL Search Params
 */
#ifndef ADA_URL_SEARCH_PARAMS_H
#define ADA_URL_SEARCH_PARAMS_H

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ada {

enum class url_search_params_iter_type {
  KEYS,
  VALUES,
  ENTRIES,
};

template <typename T, url_search_params_iter_type Type>
struct url_search_params_iter;

typedef std::pair<std::string_view, std::string_view> key_value_view_pair;

using url_search_params_keys_iter =
    url_search_params_iter<std::string_view, url_search_params_iter_type::KEYS>;
using url_search_params_values_iter =
    url_search_params_iter<std::string_view,
                           url_search_params_iter_type::VALUES>;
using url_search_params_entries_iter =
    url_search_params_iter<key_value_view_pair,
                           url_search_params_iter_type::ENTRIES>;

/**
 * @see https://url.spec.whatwg.org/#interface-urlsearchparams
 */
struct url_search_params {
  url_search_params() = default;

  /**
   * @see
   * https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-constructor.any.js
   */
  url_search_params(const std::string_view input) { initialize(input); }

  url_search_params(const url_search_params &u) = default;
  url_search_params(url_search_params &&u) noexcept = default;
  url_search_params &operator=(url_search_params &&u) noexcept = default;
  url_search_params &operator=(const url_search_params &u) = default;
  ~url_search_params() = default;

  [[nodiscard]] inline size_t size() const noexcept;

  /**
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-append
   */
  inline void append(std::string_view key, std::string_view value);

  /**
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-delete
   */
  inline void remove(std::string_view key);
  inline void remove(std::string_view key, std::string_view value);

  /**
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-get
   */
  inline std::optional<std::string_view> get(std::string_view key);

  /**
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-getall
   */
  inline std::vector<std::string> get_all(std::string_view key);

  /**
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-has
   */
  inline bool has(std::string_view key) noexcept;
  inline bool has(std::string_view key, std::string_view value) noexcept;

  /**
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-set
   */
  inline void set(std::string_view key, std::string_view value);

  /**
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-sort
   */
  inline void sort();

  /**
   * @see https://url.spec.whatwg.org/#urlsearchparams-stringification-behavior
   */
  inline std::string to_string() const;

  /**
   * Returns a simple JS-style iterator over all of the keys in this
   * url_search_params. The keys in the iterator are not unique. The valid
   * lifespan of the iterator is tied to the url_search_params. The iterator
   * must be freed when you're done with it.
   * @see https://url.spec.whatwg.org/#interface-urlsearchparams
   */
  inline url_search_params_keys_iter get_keys();

  /**
   * Returns a simple JS-style iterator over all of the values in this
   * url_search_params. The valid lifespan of the iterator is tied to the
   * url_search_params. The iterator must be freed when you're done with it.
   * @see https://url.spec.whatwg.org/#interface-urlsearchparams
   */
  inline url_search_params_values_iter get_values();

  /**
   * Returns a simple JS-style iterator over all of the entries in this
   * url_search_params. The entries are pairs of keys and corresponding values.
   * The valid lifespan of the iterator is tied to the url_search_params. The
   * iterator must be freed when you're done with it.
   * @see https://url.spec.whatwg.org/#interface-urlsearchparams
   */
  inline url_search_params_entries_iter get_entries();

  /**
   * C++ style conventional iterator support. const only because we
   * do not really want the params to be modified via the iterator.
   */
  inline auto begin() const { return params.begin(); }
  inline auto end() const { return params.end(); }
  inline auto front() const { return params.front(); }
  inline auto back() const { return params.back(); }
  inline auto operator[](size_t index) const { return params[index]; }

  /**
   * @private
   * Used to reset the search params to a new input.
   * Used primarily for C API.
   * @param input
   */
  void reset(std::string_view input);

 private:
  typedef std::pair<std::string, std::string> key_value_pair;
  std::vector<key_value_pair> params{};

  /**
   * @see https://url.spec.whatwg.org/#concept-urlencoded-parser
   */
  void initialize(std::string_view init);

  template <typename T, url_search_params_iter_type Type>
  friend struct url_search_params_iter;
};  // url_search_params

/**
 * Implements a non-conventional iterator pattern that is closer in style to
 * JavaScript's definition of an iterator.
 *
 * @see https://webidl.spec.whatwg.org/#idl-iterable
 */
template <typename T, url_search_params_iter_type Type>
struct url_search_params_iter {
  inline url_search_params_iter() : params(EMPTY) {}
  url_search_params_iter(const url_search_params_iter &u) = default;
  url_search_params_iter(url_search_params_iter &&u) noexcept = default;
  url_search_params_iter &operator=(url_search_params_iter &&u) noexcept =
      default;
  url_search_params_iter &operator=(const url_search_params_iter &u) = default;
  ~url_search_params_iter() = default;

  /**
   * Return the next item in the iterator or std::nullopt if done.
   */
  inline std::optional<T> next();

  inline bool has_next();

 private:
  static url_search_params EMPTY;
  inline url_search_params_iter(url_search_params &params_) : params(params_) {}

  url_search_params &params;
  size_t pos = 0;

  friend struct url_search_params;
};

}  // namespace ada
#endif
