#!/usr/bin/env python3

from os import environ, path
from github import Github
from lib.release import create_release

WORK_DIR = path.dirname(path.abspath(__file__)).replace('/tools/release', '')

NEXT_TAG = environ.get('NEXT_RELEASE_TAG', None)
REPO_NAME = environ.get('GITHUB_REPOSITORY', None)
TOKEN = environ.get('GITHUB_TOKEN', None)
if not NEXT_TAG or not REPO_NAME or not TOKEN:
    raise Exception('Bad environment variables. Invalid GITHUB_REPOSITORY, GITHUB_TOKEN or NEXT_RELEASE_TAG')

g = Github(TOKEN)
repository = g.get_repo(REPO_NAME)

release = create_release(repository, NEXT_TAG)
release.upload_asset('singleheader/ada.cpp')
release.upload_asset('singleheader/ada.h')
release.upload_asset('singleheader/ada_c.h')
release.upload_asset('singleheader/singleheader.zip')
