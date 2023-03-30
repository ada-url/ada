# Release Document

## Preparation

In order to release a new version of Ada, please update the
following documents:

- [CmakeLists.txt](../CmakeLists.txt)
- [Doxygen](../doxygen)
- [ada_version.h](../include/ada/ada_version.h)

## Release

- Run amalgation script using `./singleheader/amalgamate.py`
- Create a Github release with following format: `v1.0.0`
- Upload the following documents to the release
  - `./singleheader/ada.h`
  - `./singleheader/ada.cpp`
  - `./singleheader/singleheader.zip`
