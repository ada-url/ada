#!/usr/bin/env python3

import fileinput
import re


def update_cmakelists_version(new_version, file_path):
    inside_project = False
    with fileinput.FileInput(file_path, inplace=True) as cmakelists:
        for line in cmakelists:
            if "set(ADA_LIB_VERSION" in line:
                line = re.sub(r"[0-9]+\.[0-9]+\.[0-9]+", new_version, line)

            if "project(" in line:
                inside_project = True
            if inside_project:
                if "VERSION" in line:
                    line = re.sub(r"[0-9]+\.[0-9]+\.[0-9]+", new_version, line)
                    inside_project = False
            print(line, end="")
