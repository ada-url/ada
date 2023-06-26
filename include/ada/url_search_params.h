/**
 * @file url_search_params.h
 * @brief Declaration for the URL Search Params
 */
#ifndef ADA_URL_SEARCH_PARAMS_H
#define ADA_URL_SEARCH_PARAMS_H

namespace ada {

#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * @see https://url.spec.whatwg.org/#interface-urlsearchparams
 */
struct url_search_params {
  // TODO: Add missing constructors
  url_search_params() = default;
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
  void remove(std::string_view key);
  void remove(std::string_view key, std::string_view value);

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

  /**
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-set
   */
  void set(std::string_view key, std::string_view value);

  /**
   * @see https://url.spec.whatwg.org/#dom-urlsearchparams-sort
   */
  void sort();

  /**
   * @see https://url.spec.whatwg.org/#urlsearchparams-stringification-behavior
   */
  std::string to_string();

 private:
  std::vector<std::pair<std::string, std::string>> params{};
};  // url_search_params

}  // namespace ada
#endif
