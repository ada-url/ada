#include "ada.h"
#include "gtest/gtest.h"

TEST(url_search_params, append) {
  auto search_params = ada::url_search_params();
  search_params.append("key", "value");
  ASSERT_EQ(search_params.size(), 1);
  ASSERT_TRUE(search_params.has("key"));
  search_params.append("key", "value2");
  ASSERT_EQ(search_params.size(), 2);
  ASSERT_EQ(search_params.get_all("key").size(), 2);
  SUCCEED();
}

TEST(url_search_params, to_string) {
  auto search_params = ada::url_search_params();
  search_params.append("key1", "value1");
  search_params.append("key2", "value2");
  ASSERT_EQ(search_params.size(), 2);
  ASSERT_EQ(search_params.to_string(), "key1=value1&key2=value2");
  SUCCEED();
}

TEST(url_search_params, set) {
  auto search_params = ada::url_search_params();
  search_params.append("key1", "value1");
  search_params.append("key1", "value2");
  ASSERT_EQ(search_params.size(), 2);
  search_params.set("key1", "hello");
  ASSERT_EQ(search_params.size(), 1);
  ASSERT_EQ(search_params.to_string(), "key1=hello");
  SUCCEED();
}

TEST(url_search_params, remove) {
  auto search_params = ada::url_search_params();
  search_params.append("key1", "value1");
  search_params.append("key1", "value2");
  search_params.append("key2", "value2");
  search_params.remove("key2");
  ASSERT_EQ(search_params.size(), 2);
  ASSERT_EQ(search_params.to_string(), "key1=value1&key1=value2");
  search_params.remove("key1", "value2");
  ASSERT_EQ(search_params.size(), 1);
  ASSERT_EQ(search_params.to_string(), "key1=value1");
  SUCCEED();
}

TEST(url_search_params, sort) {
  auto search_params = ada::url_search_params();
  search_params.append("bbb", "second");
  search_params.append("aaa", "first");
  search_params.append("ccc", "third");
  ASSERT_EQ(search_params.size(), 3);
  search_params.sort();
  ASSERT_EQ(search_params.to_string(), "aaa=first&bbb=second&ccc=third");
  SUCCEED();
}
