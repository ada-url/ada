#!/usr/bin/env python3

from github import Github
import os
import re


def is_valid_tag(tag):
    tag_regex = r"^v\d+\.\d+\.\d+$"
    return bool(re.match(tag_regex, tag))


def create_release(repository, tag, notes):
    if not is_valid_tag(tag):
        raise Exception(f"Invalid tag: {tag}")

    try:
        repository.create_git_release(
            tag=tag, name=tag, message=notes, draft=False, prerelease=False
        )

    except Exception as e:
        raise Exception(f"Error creating release/tag {tag}: {str(e)}")


def get_release_merged_pulls(repository, last_release):
    pulls = repository.get_pulls(state="closed")
    return set(
        [
            pull
            for pull in pulls
            if pull.merged and pull.merged_at > last_release.created_at
        ]
    )


def get_new_contributors(repository, last_release):
    merged_pulls = [
        pull
        for pull in repository.get_pulls(state="closed")
        if pull.merged and pull.merged_at <= last_release.created_at
    ]
    contributors = set()
    for pull in merged_pulls:
        contributors.add(pull.user.login)

    new_contributors = set()
    release_merged_pulls = get_release_merged_pulls(repository, last_release)
    for pull in release_merged_pulls:
        contributor = pull.user.login
        if contributor not in contributors:
            new_contributors.add(contributor)
    return new_contributors


def get_last_release(repository):
    sorted_releases = sorted(
        repository.get_releases(), key=lambda r: r.created_at, reverse=True
    )

    last_release = repository
    if len(sorted_releases) >= 2:
        last_release = sorted_releases[0]

    return last_release


def whats_changed_md(repository, last_release):
    release_merged_pulls = get_release_merged_pulls(repository, last_release)
    whats_changed = set()
    for pull in release_merged_pulls:
        whats_changed.add(f"* {pull.title} by @{pull.user.login} in #{pull.number}")

    return whats_changed


def new_contributors_md(repository, last_release):
    new_contributors = get_new_contributors(repository, last_release)
    release_merged_pulls = get_release_merged_pulls(repository, last_release)

    contributors_md = set()
    for contributor in new_contributors:
        first_contribution = min(
            [pull for pull in release_merged_pulls if pull.user.login == contributor],
            key=lambda pull: pull.merged_at,
            default=None,
        )
        if first_contribution:
            contributors_md.add(
                f"* @{contributor} made their first contribution in #{first_contribution.number}"
            )

    return contributors_md


def full_changelog_md(repo_name, last_tag, next_tag):
    return f"#### Full Changelog: [{last_tag}...{next_tag}]({repo_name}/compare/{last_tag}...{next_tag})"


if __name__ == "__main__":
    repo_name = os.environ["GITHUB_REPOSITORY"]
    github_token = os.environ["GITHUB_TOKEN"]
    next_tag = os.environ["NEXT_RELEASE_TAG"]
    if not repo_name or not github_token or not next_tag:
        raise Exception(
            f"Bad environment variables. Invalid GITHUB_REPOSITORY, GITHUB_TOKEN or NEXT_RELEASE_TAG"
        )

    g = Github(github_token)
    repo = g.get_repo(repo_name)
    last_tag = get_last_release(repo)

    notes = "## What's Changed\n"
    whats_changed = whats_changed_md(repo, last_tag)
    for change in whats_changed:
        notes += f"{change}\n"

    new_contributors = get_new_contributors(repo, last_tag)
    if len(new_contributors):
        notes += "## New Contributors\n"
        for contributor in new_contributors:
            notes += f"{contributor}\n"

    change_log = full_changelog_md(repo_name, last_tag, next_tag)
    notes += change_log

    create_release(repo, next_tag, notes)
