/**
 * @file url_search_params.h
 * @brief URL query string parameter manipulation.
 *
 * This file provides the `url_search_params` class for parsing, manipulating,
 * and serializing URL query strings. It implements the URLSearchParams API
 * from the WHATWG URL Standard.
 *
 * @see https://url.spec.whatwg.org/#interface-urlsearchparams
 */
#ifndef ADA_URL_SEARCH_PARAMS_H
#define ADA_URL_SEARCH_PARAMS_H

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ada {

/**
 * @brief Iterator types for url_search_params iteration.
 */
enum class url_search_params_iter_type {
  KEYS,    /**< Iterate over parameter keys only */
  VALUES,  /**< Iterate over parameter values only */
  ENTRIES, /**< Iterate over key-value pairs */
};

template <typename T, url_search_params_iter_type Type>
struct url_search_params_iter;

/** Type alias for a key-value pair of string views. */
typedef std::pair<std::string_view, std::string_view> key_value_view_pair;

/** Iterator over search parameter keys. */
using url_search_params_keys_iter =
    url_search_params_iter<std::string_view, url_search_params_iter_type::KEYS>;
/** Iterator over search parameter values. */
using url_search_params_values_iter =
    url_search_params_iter<std::string_view,
                           url_search_params_iter_type::VALUES>;
/** Iterator over search parameter key-value pairs. */
using url_search_params_entries_iter =
    url_search_params_iter<key_value_view_pair,
                           url_search_params_iter_type::ENTRIES>;

/**
 * @brief Class for parsing and manipulating URL query strings.
 *
 * The `url_search_params` class provides methods to parse, modify, and
 * serialize URL query parameters (the part after '?' in a URL). It handles
 * percent-encoding and decoding automatically.
 *
 * All string inputs must be valid UTF-8. The caller is responsible for
 * ensuring UTF-8 validity.
 *
 * @see https://url.spec.whatwg.org/#interface-urlsearchparams
 */
struct url_search_params {
  url_search_params() = default;

  /**
   * Constructs url_search_params by parsing a query string.
   * @param input A query string (with or without leading '?'). Must be UTF-8.
   */
  explicit url_search_params(const std::string_view input) {
    initialize(input);
  }

  url_search_params(const url_search_params &u) = default;
  url_search_params(url_search_params &&u) noexcept = default;
  url_search_params &operator=(url_search_params &&u) noexcept = default;
  url_search_params &operator=(const url_search_params &u) = default;
  ~url_search_params() = default;

  /**
   * Returns the number of key-value pairs.
   * @return The total count of parameters.
   */
  [[nodiscard]] inline size_t size() const noexcept;

  /**
   * Appends a new key-value pair to the parameter list.
   * @param key The parameter name (must be valid UTF-8).
   * @param value The parameter value (must be valid UTF-8).
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-append
   */
  inline void append(std::string_view key, std::string_view value);

  /**
   * Removes all pairs with the given key.
   * @param key The parameter name to remove.
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-delete
   */
  inline void remove(std::string_view key);

  /**
   * Removes all pairs with the given key and value.
   * @param key The parameter name.
   * @param value The parameter value to match.
   */
  inline void remove(std::string_view key, std::string_view value);

  /**
   * Returns the value of the first pair with the given key.
   * @param key The parameter name to search for.
   * @return The value if found, or std::nullopt if not present.
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-get
   */
  inline std::optional<std::string_view> get(std::string_view key);

  /**
   * Returns all values for pairs with the given key.
   * @param key The parameter name to search for.
   * @return A vector of all matching values (may be empty).
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-getall
   */
  inline std::vector<std::string> get_all(std::string_view key);

  /**
   * Checks if any pair has the given key.
   * @param key The parameter name to search for.
   * @return `true` if at least one pair has this key.
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-has
   */
  inline bool has(std::string_view key) noexcept;

  /**
   * Checks if any pair matches the given key and value.
   * @param key The parameter name to search for.
   * @param value The parameter value to match.
   * @return `true` if a matching pair exists.
   */
  inline bool has(std::string_view key, std::string_view value) noexcept;

  /**
   * Sets a parameter value, replacing any existing pairs with the same key.
   * @param key The parameter name (must be valid UTF-8).
   * @param value The parameter value (must be valid UTF-8).
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-set
   */
  inline void set(std::string_view key, std::string_view value);

  /**
   * Sorts all key-value pairs by their keys using code unit comparison.
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-sort
   */
  inline void sort();

  /**
   * Serializes the parameters to a query string (without leading '?').
   * @return The percent-encoded query string.
   * @see https://url.spec.whatwg.org/#urlsearchparams-stringification-behavior
   */
  inline std::string to_string() const;

  /**
   * Returns an iterator over all parameter keys.
   * Keys may repeat if there are duplicate parameters.
   * @return An iterator yielding string_view keys.
   * @note The iterator is invalidated if this object is modified.
   */
  inline url_search_params_keys_iter get_keys();

  /**
   * Returns an iterator over all parameter values.
   * @return An iterator yielding string_view values.
   * @note The iterator is invalidated if this object is modified.
   */
  inline url_search_params_values_iter get_values();

  /**
   * Returns an iterator over all key-value pairs.
   * @return An iterator yielding key-value pair views.
   * @note The iterator is invalidated if this object is modified.
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
   * The init parameter must be valid UTF-8.
   * @see https://url.spec.whatwg.org/#concept-urlencoded-parser
   */
  void initialize(std::string_view init);

  template <typename T, url_search_params_iter_type Type>
  friend struct url_search_params_iter;
};  // url_search_params

/**
 * @brief JavaScript-style iterator for url_search_params.
 *
 * Provides a `next()` method that returns successive values until exhausted.
 * This matches the iterator pattern used in the Web Platform.
 *
 * @tparam T The type of value returned by the iterator.
 * @tparam Type The type of iteration (KEYS, VALUES, or ENTRIES).
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
   * Returns the next value in the iteration sequence.
   * @return The next value, or std::nullopt if iteration is complete.
   */
  inline std::optional<T> next();

  /**
   * Checks if more values are available.
   * @return `true` if `next()` will return a value, `false` if exhausted.
   */
  inline bool has_next() const;

 private:
  static url_search_params EMPTY;
  inline url_search_params_iter(url_search_params &params_) : params(params_) {}

  url_search_params &params;
  size_t pos = 0;

  friend struct url_search_params;
};

}  // namespace ada
#endif
