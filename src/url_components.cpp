#include "ada.h"
#include "ada/helpers.h"
#include "ada/url_components.h"

#include <numeric>
#include <string>

namespace ada {

[[nodiscard]] bool url_components::check_offset_consistency() const noexcept {
  /**
   * https://user:pass@example.com:1234/foo/bar?baz#quux
   *       |     |    |          | ^^^^|       |   |
   *       |     |    |          | |   |       |   `----- hash_start
   *       |     |    |          | |   |       `--------- search_start
   *       |     |    |          | |   `----------------- pathname_start
   *       |     |    |          | `--------------------- port
   *       |     |    |          `----------------------- host_end
   *       |     |    `---------------------------------- host_start
   *       |     `--------------------------------------- username_end
   *       `--------------------------------------------- protocol_end
   */
  // These conditions can be made more strict.
  uint32_t index = 0;

  if (protocol_end == url_components::omitted) {
    return false;
  }
  if (protocol_end < index) {
    return false;
  }
  index = protocol_end;

  if (username_end == url_components::omitted) {
    return false;
  }
  if (username_end < index) {
    return false;
  }
  index = username_end;

  if (host_start == url_components::omitted) {
    return false;
  }
  if (host_start < index) {
    return false;
  }
  index = host_start;

  if (port != url_components::omitted) {
    if (port > 0xffff) {
      return false;
    }
    uint32_t port_length = helpers::fast_digit_count(port) + 1;
    if (index + port_length < index) {
      return false;
    }
    index += port_length;
  }

  if (pathname_start == url_components::omitted) {
    return false;
  }
  if (pathname_start < index) {
    return false;
  }
  index = pathname_start;

  if (search_start != url_components::omitted) {
    if (search_start < index) {
      return false;
    }
    index = search_start;
  }

  if (hash_start != url_components::omitted) {
    if (hash_start < index) {
      return false;
    }
    index = hash_start;
  }

  return true;
}

[[nodiscard]] std::string url_components::to_string() const {
  std::string answer;
  auto back = std::back_insert_iterator(answer);
  answer.append("{\n");

  answer.append("\t\"protocol_end\":\"");
  helpers::encode_json(std::to_string(protocol_end), back);
  answer.append("\",\n");

  answer.append("\t\"username_end\":\"");
  helpers::encode_json(std::to_string(username_end), back);
  answer.append("\",\n");

  answer.append("\t\"host_start\":\"");
  helpers::encode_json(std::to_string(host_start), back);
  answer.append("\",\n");

  answer.append("\t\"host_end\":\"");
  helpers::encode_json(std::to_string(host_end), back);
  answer.append("\",\n");

  answer.append("\t\"port\":\"");
  helpers::encode_json(std::to_string(port), back);
  answer.append("\",\n");

  answer.append("\t\"pathname_start\":\"");
  helpers::encode_json(std::to_string(pathname_start), back);
  answer.append("\",\n");

  answer.append("\t\"search_start\":\"");
  helpers::encode_json(std::to_string(search_start), back);
  answer.append("\",\n");

  answer.append("\t\"hash_start\":\"");
  helpers::encode_json(std::to_string(hash_start), back);
  answer.append("\",\n");

  answer.append("\n}");
  return answer;
}

}  // namespace ada
