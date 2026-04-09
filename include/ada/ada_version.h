/**
 * @file ada_version.h
 * @brief Definitions for Ada's version number.
 */
#ifndef ADA_ADA_VERSION_H
#define ADA_ADA_VERSION_H

#define ADA_VERSION "3.4.4"

/* C-compatible numeric macros (usable without C++ namespace). */
#define ADA_VERSION_MAJOR_NUM 3
#define ADA_VERSION_MINOR_NUM 4
#define ADA_VERSION_REVISION_NUM 3

#ifdef __cplusplus
namespace ada {

enum {
  ADA_VERSION_MAJOR = 3,
  ADA_VERSION_MINOR = 4,
  ADA_VERSION_REVISION = 4,
};

}  // namespace ada
#endif /* __cplusplus */

#endif  // ADA_ADA_VERSION_H
