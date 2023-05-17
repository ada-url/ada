#include "ada.h"
#include <emscripten/emscripten.h>
#include <emscripten/bind.h>

using namespace emscripten;

struct parse_result {
  std::string result;
  std::string href;
  uint32_t type;
  ada::url_components components;
};

parse_result parse(const std::string &input) {
  auto out = ada::parse<ada::url_aggregator>(input);
  parse_result result;
  if (!out.has_value()) {
    result.result = "fail";
  } else {
    result.result = "success";
    result.href = std::string(out->get_href());
    result.type = out->type;
    result.components = out->get_components();
  }
  return result;
}

EMSCRIPTEN_BINDINGS(url_components) {
  class_<parse_result>("Result")
      .property("result", &parse_result::result)
      .property("href", &parse_result::href)
      .property("type", &parse_result::type)
      .property("components", &parse_result::components);
  class_<ada::url_components>("URLComponents")
      .property("protocol_end", &ada::url_components::protocol_end)
      .property("username_end", &ada::url_components::username_end)
      .property("host_start", &ada::url_components::host_start)
      .property("host_end", &ada::url_components::host_end)
      .property("port", &ada::url_components::port)
      .property("pathname_start", &ada::url_components::pathname_start)
      .property("search_start", &ada::url_components::search_start)
      .property("hash_start", &ada::url_components::hash_start);

  function("parse", &parse);
}