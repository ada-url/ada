#!/usr/bin/env python3

import os
import lib.versions as update_versions
from lib.release import is_valid_tag

WORK_DIR = os.path.dirname(os.path.abspath(__file__)).replace("/tools/release", "")

ADA_VERSION_H = f"{WORK_DIR}/include/ada/ada_version.h"
DOXYGEN = f"{WORK_DIR}/doxygen"
CMAKE_LISTS = f"{WORK_DIR}/CMakeLists.txt"

NEXT_TAG = os.environ["NEXT_RELEASE_TAG"]
if not NEXT_TAG or not is_valid_tag(NEXT_TAG):
    raise Exception(f"Bad environment variables. Invalid NEXT_RELEASE_TAG {NEXT_TAG}.")

NEXT_TAG = NEXT_TAG[1:]  # from v1.0.0 to 1.0.0

update_versions.update_ada_version_h(NEXT_TAG, ADA_VERSION_H)
update_versions.update_doxygen_version(NEXT_TAG, DOXYGEN)
update_versions.update_cmakelists_version(NEXT_TAG, CMAKE_LISTS)
