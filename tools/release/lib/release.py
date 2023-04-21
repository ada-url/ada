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

    except Exception as exp:
        raise Exception(
            f"create_release: Error creating release/tag {tag}: {str(exp)}"
        ) from exp


def get_release_merged_pulls(repository, last_release):
    pulls = repository.get_pulls(state="closed")
    if not last_release:
        return sorted(
            [pull for pull in pulls if pull.merged], key=lambda pull: pull.number
        )
    return sorted(
        [
            pull
            for pull in pulls
            if pull.merged and pull.merged_at > last_release.created_at
        ],
        key=lambda pull: pull.number,
    )


def get_new_contributors(repository, last_release):
    # Get list of contributors up to the last release
    merged_pulls = [
        pull
        for pull in repository.get_pulls(state="closed")
        if pull.merged and pull.merged_at <= last_release.created_at
    ]
    contributors = set()
    for pull in merged_pulls:
        contributors.add(pull.user.login)

    # Adds into the dict the new contributors and thair respective merged PRs
    new_contributors = {}
    release_merged_pulls = get_release_merged_pulls(repository, last_release)
    for pull in release_merged_pulls:
        contributor = pull.user.login
        if contributor not in contributors:
            if contributor not in new_contributors.keys():
                new_contributors[contributor] = [pull]
            else:
                new_contributors[contributor] += [pull]

    for contributor in new_contributors.keys():
        new_contributors[contributor] = sorted(
            new_contributors[f"{contributor}"], key=lambda pull: pull.merged_at
        )

    return new_contributors


def get_last_release(repository):
    sorted_releases = sorted(
        repository.get_releases(), key=lambda r: r.created_at, reverse=True
    )

    if len(sorted_releases) >= 1:
        return sorted_releases[0]

    return None


def whats_changed_md(repository, last_release):
    release_merged_pulls = get_release_merged_pulls(repository, last_release)
    whats_changed = []
    for pull in release_merged_pulls:
        whats_changed.append(
            f"* {pull.title} by @{pull.user.login} in https://github.com/{repository.full_name}/pull/{pull.number}"
        )

    return whats_changed


def new_contributors_md(repository, last_release):
    new_contributors = get_new_contributors(repository, last_release)

    contributors_md = []
    for contributor in new_contributors.items():
        pr_number = contributor[1][0].number  # 0 is the first one merged
        contributors_md.append(
            f"* @{contributor[0]} made their first contribution in https://github.com/{repository.full_name}/pull/{pr_number}"
        )

    return contributors_md


def full_changelog_md(repository_name, last_tag_name, next_tag_name):
    return f"**Full Changelog**: https://github.com/{repository_name}/compare/{last_tag_name}...{next_tag_name}"


def contruct_release_notes(repository, next_tag_name):
    last_tag = get_last_release(repository)
    whats_changed = whats_changed_md(repository, last_tag)
    new_contributors = new_contributors_md(repository, last_tag)

    notes = "## What's Changed\n"
    for changes in whats_changed:
        notes += changes + "\n"

    notes += "\n"

    if new_contributors:
        notes += "## New Contributors\n"
        for new_contributor in new_contributors:
            notes += new_contributor + "\n"

        notes += "\n"

    if last_tag:
        notes += full_changelog_md(repository.full_name, last_tag.title, next_tag_name)

    return notes
