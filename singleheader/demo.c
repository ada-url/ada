#include "ada_c.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

static void ada_print(ada_string string) {
  printf("%.*s\n", (int)string.length, string.data);
}

int main(int c, char *arg[] ) {
  ada_url url = ada_parse("https://username:password@www.google.com:8080/"
      "pathname?query=true#hash-exists");
  if(!ada_is_valid(url)) { puts("failure"); return EXIT_FAILURE; }
  ada_print(ada_get_href(url)); // prints https://username:password@host:8080/pathname?query=true#hash-exists
  ada_print(ada_get_protocol(url)); // prints https:
  ada_print(ada_get_username(url)); // prints username
  ada_set_href(url, "https://www.yagiz.co");
  if(!ada_is_valid(url)) { puts("failure"); return EXIT_FAILURE; }
  ada_set_hash(url, "new-hash");
  ada_set_hostname(url, "new-host");
  ada_set_host(url, "changed-host:9090");
  ada_set_pathname(url, "new-pathname");
  ada_set_search(url, "new-search");
  ada_set_protocol(url, "wss");
  ada_print(ada_get_href(url)); // will print wss://changed-host:9090/new-pathname?new-search#new-hash
  ada_free(url);
  return EXIT_SUCCESS;
}
