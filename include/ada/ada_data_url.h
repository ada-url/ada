#ifndef ADA_DATA_URL_H
#define ADA_DATA_URL_H

#include <string_view>

namespace ada::data_url {
// https://fetch.spec.whatwg.org/#data-url-struct
struct data_url {
  data_url() = default;
  data_url(const data_url &m) = default;
  data_url(data_url &&m) noexcept = default;
  data_url &operator=(data_url &&m) noexcept = default;
  data_url &operator=(const data_url &m) = default;
  ~data_url() = default;

  bool is_valid = true;
  std::string body{};
  std::string essence{};
};

ada::data_url::data_url parse_data_url(std::string_view data_url);

std::string collect_sequence_of_code_points(char c, const std::string &input,
                                            size_t &position);

bool isASCIIWhiteSpace(char c);

std::string removeASCIIWhiteSpace(const std::string &input, bool leading,
                                  bool trailing);

static constexpr bool is_base64(std::string_view input);

}  // namespace ada::data_url

#endif  // ADA_DATA_URL_H
