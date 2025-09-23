#!/usr/bin/env python3

import re
from github import Repository, GitRelease


def is_valid_tag(tag: str) -> bool:
    tag_regex = r'^v\d+\.\d+\.\d+$'
    return bool(re.match(tag_regex, tag))


def create_release(repository: Repository, tag: str) -> GitRelease:
    if not is_valid_tag(tag):
        raise Exception(f'Invalid tag: {tag}')

    try:
        return repository.create_git_release(
            tag=tag, name=tag, draft=True, prerelease=False, generate_release_notes=True
        )
    except Exception as exp:
        raise Exception(f'create_release: Error creating release/tag {tag}: {exp!s}') from exp
