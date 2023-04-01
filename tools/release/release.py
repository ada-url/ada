#!/usr/bin/env python3

from github import Github
import os


def get_merged_pull_requests(repo, last_release):
    pulls = repo.get_pulls(state='closed')
    return [pull for pull in pulls if pull.merged and pull.merged_at > last_release.created_at]


def get_new_contributors(repo, merged_pulls):
    contributors = set()
    repo.get_contributors()
    print(repo.get_contributors())
    for pull in merged_pulls:
        contributor = pull.user.login
        if contributor not in repo.get_contributors():
            contributors.add(contributor)
    return contributors


def whats_changed():
    repo_name = os.environ["GITHUB_REPOSITORY"]
    github_token = os.environ["GITHUB_TOKEN"]
    g = Github(github_token)
    repo = g.get_repo(repo_name)

    sorted_releases = sorted(repo.get_releases(), key=lambda r: r.created_at, reverse=True)
    last_release = repo

    if len(sorted_releases) >= 2:
        previous_release = sorted_releases[1]
        last_release = sorted_releases[1]
        print(f"Previous release: {previous_release.tag_name}")
    else:
        print("No previous release found")

    merged_pulls = get_merged_pull_requests(repo, last_release)

    # get new contributors since last release
    get_new_contributors(repo, merged_pulls)

    # print details of merged pull requests since last release
    for pull in merged_pulls:
        print(f"{pull.title} by @{pull.user.login} in #{pull.number}")


whats_changed()
