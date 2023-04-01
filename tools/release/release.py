#!/usr/bin/env python3

from github import Github
import os


def get_release_merged_pulls(repository, last_release):
    pulls = repository.get_pulls(state="closed")
    return [
        pull
        for pull in pulls
        if pull.merged and pull.merged_at > last_release.created_at
    ]


def get_new_contributors(repository):
    last_release = get_last_release(repository)
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
        last_release = sorted_releases[1]

    return last_release


def whats_changed(repository):
    last_release = get_last_release(repository)
    release_merged_pulls = get_release_merged_pulls(repository, last_release)
    release_changes = ""
    for pull in release_merged_pulls:
        release_changes += f"{pull.title} by @{pull.user.login} in #{pull.number}\n"

    release_changes += "\n"
    return changes


if __name__ == "__main__":
    repo_name = os.environ["GITHUB_REPOSITORY"]
    github_token = os.environ["GITHUB_TOKEN"]
    if not repo_name or not github_token:
        raise Exception(
            f"Bad environment variables. Invalid GITHUB_REPOSITORY or GITHUB_TOKEN"
        )

    g = Github(github_token)
    repo = g.get_repo(repo_name)

    changes = whats_changed(repo)
    nc = get_new_contributors(repo)
