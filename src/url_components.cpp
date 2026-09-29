#include "ada/helpers.h"
#include "ada/url_components-inl.h"

#include <iterator>
#include <string>
#include <string_view>
#include <utility>

namespace ada {

[[nodiscard]] std::string url_components::to_string() const {
  std::string answer;
  auto back = std::back_insert_iterator(answer);
  answer.append("{\n");

  const std::pair<std::string_view, uint32_t> fields[] = {
      {"protocol_end", protocol_end},
      {"username_end", username_end},
      {"host_start", host_start},
      {"host_end", host_end},
      {"port", port},
      {"pathname_start", pathname_start},
      {"search_start", search_start},
      {"hash_start", hash_start},
  };
  for (const auto& [name, value] : fields) {
    answer.append("\t\"");
    answer.append(name);
    answer.append("\":\"");
    helpers::encode_json(std::to_string(value), back);
    answer.append("\",\n");
  }

  answer.append("\n}");
  return answer;
}

}  // namespace ada
