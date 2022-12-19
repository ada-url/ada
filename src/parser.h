#ifndef ADA_PARSER_H
#define ADA_PARSER_H

#include <optional>

namespace ada {

  class Parser {

  public:
    Parser(const char* input, std::optional<ada::URL> optional_base_url, std::optional<ada::encoding_type> encoding, std::optional<ada::state> state);
    ada::URL getURL();

  private:
    void parseState();

    char* buffer = nullptr;
    bool at_sign_seen = false;
    bool inside_brackets = false;
    bool password_token_seen = false;
    char* pointer;

    ada::encoding_type encoding = ada::encoding_type::UTF8;
    ada::state state = SCHEME_START;

    ada::URL url;
    std::optional<ada::URL> base_url;
  }; // class Parser

}

#endif // ADA_PARSER_H
