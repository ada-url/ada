#!/usr/bin/env python3
#
# Creates the amalgamated source files.
#

import zipfile
import sys
import os.path
import subprocess
import os
import re
import shutil
import datetime
if sys.version_info[0] < 3:
    sys.stdout.write("Sorry, requires Python 3.x or better\n")
    sys.exit(1)

SCRIPTPATH = os.path.dirname(os.path.abspath(sys.argv[0]))
PROJECTPATH = os.path.dirname(SCRIPTPATH)
print(f"SCRIPTPATH={SCRIPTPATH} PROJECTPATH={PROJECTPATH}")

if "AMALGAMATE_SOURCE_PATH" not in os.environ:
    AMALGAMATE_SOURCE_PATH = os.path.join(PROJECTPATH, "src")
else:
    AMALGAMATE_SOURCE_PATH = os.environ["AMALGAMATE_SOURCE_PATH"]
if "AMALGAMATE_INCLUDE_PATH" not in os.environ:
    AMALGAMATE_INCLUDE_PATH = os.path.join(PROJECTPATH, "include")
else:
    AMALGAMATE_INCLUDE_PATH = os.environ["AMALGAMATE_INCLUDE_PATH"]
if "AMALGAMATE_OUTPUT_PATH" not in os.environ:
    AMALGAMATE_OUTPUT_PATH = os.path.join(SCRIPTPATH)
else:
    AMALGAMATE_OUTPUT_PATH = os.environ["AMALGAMATE_OUTPUT_PATH"]

# this list excludes the "src/generic headers"
ALLCFILES = ["ada.cpp"]

# order matters
ALLCHEADERS = ["ada.h"]

found_includes = []

current_implementation=''

def doinclude(fid: str, file: str, line: str, origin: str) -> None:

    p = os.path.join(AMALGAMATE_INCLUDE_PATH, file)
    pi = os.path.join(AMALGAMATE_SOURCE_PATH, file)

    if os.path.exists(p):
        if file not in found_includes:
            found_includes.append(file)
            dofile(fid, AMALGAMATE_INCLUDE_PATH, file)
        else:
            pass
    elif os.path.exists(pi):
        if file not in found_includes:
            found_includes.append(file)
            dofile(fid, AMALGAMATE_SOURCE_PATH, file)
        else:
            pass
    else:
        # If we don't recognize it, just emit the #include
        print("unrecognized:", file, " from ", line, " in ", origin)
        print(line, file=fid)

def dofile(fid: str, prepath: str, filename: str) -> None:
    file = os.path.join(prepath, filename)
    RELFILE = os.path.relpath(file, PROJECTPATH)
    # Last lines are always ignored. Files should end by an empty lines.
    print(f"/* begin file {RELFILE} */", file=fid)
    includepattern = re.compile('\\s*#\\s*include "(.*)"')
    with open(file, 'r') as fid2:
        for line in fid2:
            line = line.rstrip('\n')
            s = includepattern.search(line)
            if s:
                includedfile = s.group(1)
                if includedfile == "ada.h" and filename == "ada.cpp":
                    print(line, file=fid)
                    continue

                if includedfile.startswith('../'):
                    includedfile = includedfile[2:]
                # we explicitly include ada headers, one time each
                doinclude(fid, includedfile, line, filename)
            else:
                print(line, file=fid)
    print(f"/* end file {RELFILE} */", file=fid)


# Get the generation date from git, so the output is reproducible.
# The %ci specifier gives the unambiguous ISO 8601 format, and
# does not change with locale and timezone at time of generation.
# Forcing it to be UTC is difficult, because it needs to be portable
# between gnu date and busybox date.
try:
    timestamp = subprocess.run(['git', 'show', '-s', '--format=%ci', 'HEAD'],
                           stdout=subprocess.PIPE).stdout.decode('utf-8').strip()
except:
    print("git not found, timestamp based on current time")
    timestamp = str(datetime.datetime.now())
print(f"timestamp is {timestamp}")

os.makedirs(AMALGAMATE_OUTPUT_PATH, exist_ok=True)
AMAL_H = os.path.join(AMALGAMATE_OUTPUT_PATH, "ada.h")
AMAL_C = os.path.join(AMALGAMATE_OUTPUT_PATH, "ada.cpp")
DEMOCPP = os.path.join(AMALGAMATE_OUTPUT_PATH, "cpp")
README = os.path.join(AMALGAMATE_OUTPUT_PATH, "README.md")

print(f"Creating {AMAL_H}")
amal_h = open(AMAL_H, 'w')
print(f"/* auto-generated on {timestamp}. Do not edit! */", file=amal_h)
for h in ALLCHEADERS:
    doinclude(amal_h, h, f"ERROR {h} not found", h)

amal_h.close()
print()
print()
print(f"Creating {AMAL_C}")
amal_c = open(AMAL_C, 'w')
print(f"/* auto-generated on {timestamp}. Do not edit! */", file=amal_c)
for c in ALLCFILES:
    doinclude(amal_c, c, f"ERROR {c} not found", c)

amal_c.close()

# copy the README and DEMOCPP
if SCRIPTPATH != AMALGAMATE_OUTPUT_PATH:
  shutil.copy2(os.path.join(SCRIPTPATH,"demo.cpp"),AMALGAMATE_OUTPUT_PATH)
  shutil.copy2(os.path.join(SCRIPTPATH,"demo.c"),AMALGAMATE_OUTPUT_PATH)
  shutil.copy2(os.path.join(SCRIPTPATH,"README.md"),AMALGAMATE_OUTPUT_PATH)

shutil.copy2(os.path.join(AMALGAMATE_INCLUDE_PATH,"ada_c.h"),AMALGAMATE_OUTPUT_PATH)

zf = zipfile.ZipFile(os.path.join(AMALGAMATE_OUTPUT_PATH,'singleheader.zip'), 'w', zipfile.ZIP_DEFLATED)
zf.write(os.path.join(AMALGAMATE_OUTPUT_PATH,"ada.cpp"), "ada.cpp")
zf.write(os.path.join(AMALGAMATE_OUTPUT_PATH,"ada.h"), "ada.h")
zf.write(os.path.join(AMALGAMATE_INCLUDE_PATH,"ada_c.h"), "ada_c.h")


print("Done with all files generation.")

print(f"Files have been written to directory: {AMALGAMATE_OUTPUT_PATH}/")
print("Done with all files generation.")

