#include "ada.h"
#include "gtest/gtest.h"

TEST(url_search_params, append) {
  auto search_params = ada::url_search_params();
  search_params.append("key", "value");
  ASSERT_EQ(search_params.get_size(), 1);
  ASSERT_TRUE(search_params.has("key"));
  search_params.append("key", "value2");
  ASSERT_EQ(search_params.get_size(), 2);
  ASSERT_EQ(search_params.get_all("key").size(), 2);
  SUCCEED();
}
