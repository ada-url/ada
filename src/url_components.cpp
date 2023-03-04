#include "ada.h"
#include "ada/helpers.h"

#include <numeric>
#include <string>

namespace ada {

  std::string url_components::to_string() const {
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

} // namespace ada
