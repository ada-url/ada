#!/usr/bin/env python3

import os
from github import Github
import lib.release as release

WORK_DIR = os.path.dirname(os.path.abspath(__file__)).replace("/tools/release", "")

NEXT_TAG = os.environ["NEXT_RELEASE_TAG"]
REPO_NAME = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["GITHUB_TOKEN"]
if not NEXT_TAG or not REPO_NAME or not TOKEN:
    raise Exception(
        "Bad environment variables. Invalid GITHUB_REPOSITORY, GITHUB_TOKEN or NEXT_RELEASE_TAG"
    )

g = Github(TOKEN)
repo = g.get_repo(REPO_NAME)

release_notes = release.contruct_release_notes(repo, NEXT_TAG)

release.create_release(repo, NEXT_TAG, release_notes)

release = repo.get_release(NEXT_TAG)
release.upload_asset("singleheader/ada.cpp")
release.upload_asset("singleheader/ada.h")
release.upload_asset("singleheader/ada_c.h")
release.upload_asset("singleheader/singleheader.zip")
