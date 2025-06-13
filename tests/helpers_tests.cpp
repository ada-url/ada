#include "ada.h"
#include "gtest/gtest.h"

TEST(helpers_tests, is_windows_file_path) {
  // Valid Windows paths
  ASSERT_TRUE(ada::helpers::is_windows_file_path("C:\\path\\file.node"));
  ASSERT_TRUE(ada::helpers::is_windows_file_path("D:\\folder\\file.exe"));
  ASSERT_TRUE(ada::helpers::is_windows_file_path("C:/path/file.node"));
  ASSERT_TRUE(
      ada::helpers::is_windows_file_path("Z:\\deep\\nested\\path\\file.txt"));
  ASSERT_TRUE(ada::helpers::is_windows_file_path("A:\\file"));

  // Invalid paths
  ASSERT_FALSE(ada::helpers::is_windows_file_path(""));    // Empty string
  ASSERT_FALSE(ada::helpers::is_windows_file_path("C"));   // Too short
  ASSERT_FALSE(ada::helpers::is_windows_file_path("C:"));  // Missing slash
  ASSERT_FALSE(
      ada::helpers::is_windows_file_path("file:///C:/path/file.node"));  // URL
  ASSERT_FALSE(
      ada::helpers::is_windows_file_path("https://example.com"));  // URL
  ASSERT_FALSE(
      ada::helpers::is_windows_file_path("/path/to/file"));  // Unix path
  ASSERT_FALSE(
      ada::helpers::is_windows_file_path("relative/path"));  // Relative path
  ASSERT_FALSE(
      ada::helpers::is_windows_file_path("1:\\path"));  // Invalid drive letter
  ASSERT_FALSE(
      ada::helpers::is_windows_file_path("C|\\path"));  // Invalid separator
  ASSERT_FALSE(ada::helpers::is_windows_file_path(
      "C:\\"));  // Just drive letter and slash
}