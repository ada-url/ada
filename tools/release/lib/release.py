#!/usr/bin/env python3

import re
from typing import Optional, List, Set, Union, Type
from github.PullRequest import PullRequest
from github.GitRelease import GitRelease
from github.Repository import Repository


def is_valid_tag(tag: str) -> bool:
    tag_regex = r"^v\d+\.\d+\.\d+$"
    return bool(re.match(tag_regex, tag))


def create_release(
    repository: Repository, tag: str, notes: str
) -> Union[None, Type[Exception]]:
    if not is_valid_tag(tag):
        raise Exception(f"Invalid tag: {tag}")

    try:
        repository.create_git_release(
            tag=tag, name=tag, message=notes, draft=False, prerelease=False
        )

    except Exception as exp:
        raise Exception(
            f"create_release: Error creating release/tag {tag}: {exp!s}"
        ) from exp


def get_sorted_merged_pulls(
    pulls: List[PullRequest], last_release: Optional[GitRelease]
) -> List[PullRequest]:
    # Get merged pulls after last release
    if not last_release:
        return sorted(
            (
                pull
                for pull in pulls
                if pull.merged
                and pull.base.ref == "main"
                and not pull.title.startswith("chore: release")
                and not pull.user.login.startswith("github-actions")
            ),
            key=lambda pull: pull.merged_at,
        )

    return sorted(
        (
            pull
            for pull in pulls
            if pull.merged
            and pull.base.ref == "main"
            and (pull.merged_at > last_release.created_at)
            and not pull.title.startswith("chore: release")
            and not pull.user.login.startswith("github-actions")
        ),
        key=lambda pull: pull.merged_at,
    )


def get_pr_contributors(pull_request: PullRequest) -> List[str]:
    contributors = set()
    for commit in pull_request.get_commits():
        commit_message = commit.commit.message
        if commit_message.startswith("Co-authored-by:"):
            coauthor = commit_message.split("<")[0].split(":")[-1].strip()
            contributors.add(coauthor)
        else:
            author = commit.author
            if author:
                contributors.add(author.login)
    return sorted(list(contributors), key=str.lower)


def get_old_contributors(
    pulls: List[PullRequest], last_release: Optional[GitRelease]
) -> Set[str]:
    contributors = set()
    if last_release:
        merged_pulls = [
            pull
            for pull in pulls
            if pull.merged and pull.merged_at <= last_release.created_at
        ]

        for pull in merged_pulls:
            pr_contributors = get_pr_contributors(pull)
            for contributor in pr_contributors:
                contributors.add(contributor)

    return contributors


def get_new_contributors(
    old_contributors: List[str], merged_pulls: List[PullRequest]
) -> List[str]:
    new_contributors = set()
    for pull in merged_pulls:
        pr_contributors = get_pr_contributors(pull)
        for contributor in pr_contributors:
            if contributor not in old_contributors:
                new_contributors.add(contributor)

    return sorted(list(new_contributors), key=str.lower)


def get_last_release(releases: List[GitRelease]) -> Optional[GitRelease]:
    sorted_releases = sorted(releases, key=lambda r: r.created_at, reverse=True)

    if sorted_releases:
        return sorted_releases[0]

    return None


def multiple_contributors_mention_md(contributors: List[str]) -> str:
    contrib_by = ""
    if len(contributors) <= 1:
        for contrib in contributors:
            contrib_by += f"@{contrib}"
    else:
        for contrib in contributors:
            contrib_by += f"@{contrib}, "

        contrib_by = contrib_by[:-2]
        last_comma = contrib_by.rfind(", ")
        contrib_by = (
            contrib_by[:last_comma].strip()
            + " and "
            + contrib_by[last_comma + 1 :].strip()
        )
    return contrib_by


def whats_changed_md(repo_full_name: str, merged_pulls: List[PullRequest]) -> List[str]:
    whats_changed = []
    for pull in merged_pulls:
        contributors = get_pr_contributors(pull)
        contrib_by = multiple_contributors_mention_md(contributors)

        whats_changed.append(
            f"* {pull.title} by {contrib_by} in https://github.com/{repo_full_name}/pull/{pull.number}"
        )

    return whats_changed


def get_first_contribution(
    merged_pulls: List[str], contributor: str
) -> Optional[PullRequest]:
    for pull in merged_pulls:
        contrubutors = get_pr_contributors(pull)
        if contributor in contrubutors:
            return pull

    # ? unreachable
    return None


def new_contributors_md(
    repo_full_name: str, merged_pulls: List[PullRequest], new_contributors: List[str]
) -> List[str]:
    contributors_by_pr = {}
    contributors_md = []
    for contributor in new_contributors:
        first_contrib = get_first_contribution(merged_pulls, contributor)

        if not first_contrib:
            continue

        if first_contrib.number not in contributors_by_pr.keys():
            contributors_by_pr[first_contrib.number] = [contributor]
        else:
            contributors_by_pr[first_contrib.number] += [contributor]

    contributors_by_pr = dict(sorted(contributors_by_pr.items()))
    for pr_number, contributors in contributors_by_pr.items():
        contributors.sort(key=str.lower)
        contrib_by = multiple_contributors_mention_md(contributors)

        contributors_md.append(
            f"* {contrib_by} made their first contribution in https://github.com/{repo_full_name}/pull/{pr_number}"
        )

    return contributors_md


def full_changelog_md(
    repository_name: str, last_tag_name: str, next_tag_name: str
) -> Optional[str]:
    if not last_tag_name:
        return None
    return f"**Full Changelog**: https://github.com/{repository_name}/compare/{last_tag_name}...{next_tag_name}"


def contruct_release_notes(repository: Repository, next_tag_name: str) -> str:
    repo_name = repository.full_name
    last_release = get_last_release(repository.get_releases())
    all_pulls = repository.get_pulls(state="closed")

    sorted_merged_pulls = get_sorted_merged_pulls(all_pulls, last_release)
    old_contributors = get_old_contributors(all_pulls, last_release)
    new_contributors = get_new_contributors(old_contributors, sorted_merged_pulls)

    whats_changed = whats_changed_md(repo_name, sorted_merged_pulls)

    new_contrib_md = new_contributors_md(
        repo_name, sorted_merged_pulls, new_contributors
    )

    notes = "## What's changed\n"
    for changes in whats_changed:
        notes += changes + "\n"

    notes += "\n"

    if new_contributors:
        notes += "## New Contributors\n"
        for new_contributor in new_contrib_md:
            notes += new_contributor + "\n"

        notes += "\n"

    if last_release:
        notes += full_changelog_md(
            repository.full_name, last_release.title, next_tag_name
        )

    return notes
