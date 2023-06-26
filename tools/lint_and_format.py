#!/usr/bin/env python3
#
# Formats C++ code using clang-format.
#

import os
import sys
import subprocess
import argparse

parser = argparse.ArgumentParser(
    description="Format C/C++ code using clang-format."
)
parser.add_argument(
    "operation",
    choices=["check", "format"],
    help='Operation to perform: "check" to check for formatting errors, or "format" to fix formatting errors.',
)
parser.add_argument(
    "--extensions",
    "-e",
    nargs="+",
    default=[".cpp", ".cc", ".c", ".h", ".hpp"],
    help="List of file extensions to check or format (default: .cpp .cc .c .h .hpp)",
)

args = parser.parse_args()


ROOT_DIR = (
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"])
    .strip()
    .decode("utf-8")
)

exclude_dirs = ('.git', '.cache', 'build', 'dependencies', 'docs')
file_list = [os.path.join(dirpath, filename)
             for dirpath, _, filenames in os.walk(ROOT_DIR)
             for filename in filenames
             if any(filename.endswith(ext) for ext in args.extensions)
             and not any(exclude_dir in dirpath for exclude_dir in exclude_dirs)]


def clang_check(file_path: str) -> None:
    try:
        diff_output = subprocess.check_output(
            ["clang-format", "-output-replacements-xml", "-style=file", file_path], stderr=subprocess.STDOUT,
        )
        if b"<replacement " in diff_output:
            print(f"Error: {file_path} needs formatting")
            sys.exit(1)

    except subprocess.CalledProcessError as error:
        print(f'Error: {error.output.decode("utf-8")}')
        sys.exit(1)


def clang_format(file_path: str) -> None:
    diff_output = subprocess.check_output(
        ["clang-format", "-output-replacements-xml", "-style=file", file_path], stderr=subprocess.STDOUT,
    )

    if b"<replacement " in diff_output:
        print(f"Formatting: {file_path}")
        try:
            subprocess.check_call(["clang-format", "-i", "-style=file", file_path])
        except subprocess.CalledProcessError as error:
            print(f'Error: {error.output.decode("utf-8")}')
            sys.exit(1)


def clang_format_verify() -> str:
    version_output = subprocess.check_output(
        ["clang-format", "--version"], stderr=subprocess.STDOUT,
    ).decode("utf-8").split(" ")
    if "version" in version_output :
        return version_output[version_output.index("version") + 1]

    return ""


clang_format_version = clang_format_verify()

for file_path in file_list:
    if args.operation == "check":
        clang_check(file_path)
    elif args.operation == "format":
        clang_format(file_path)


print("Done!")
