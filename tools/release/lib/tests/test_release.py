from .. import release
from datetime import datetime
from collections import namedtuple

Release = namedtuple("Release", ["title", "created_at"])
User = namedtuple("User", ["login"])
Commit = namedtuple("Commit", ["author", "commit"])
CommitMessage = namedtuple("CommitMessage", ["message"])
PullRequestBase = namedtuple("PullRequestBase", "ref")
PullRequestTuple = namedtuple(
    "PullRequest",
    ["title", "number", "state", "base", "merged", "merged_at", "user", "commits"],
)


class PullRequest(PullRequestTuple):
    def get_commits(self):
        return self.commits


class RepoStub:
    def __init__(self):
        self.created_at = datetime(2023, 1, 1)
        self.full_name = "ada-url/ada"

    @staticmethod
    def get_releases() -> list:
        return [
            Release("v1.0.1", datetime(2023, 2, 1)),
            Release("v1.0.3", datetime(2023, 4, 1)),
            Release("v1.0.2", datetime(2023, 3, 1)),
        ]

    @staticmethod
    def get_pulls(state="closed"):
        return list(
            filter(
                lambda pull: pull.state == state,
                [
                    PullRequest(
                        title="Feature 1",
                        number=1,
                        state="open",
                        merged=False,
                        base=PullRequestBase("main"),
                        merged_at=datetime(2023, 2, 2),
                        user=User("contributor_1"),
                        commits=[
                            Commit(
                                User("contributor_1"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("contributor_1"),
                                CommitMessage("src: sample commit 2"),
                            ),
                            Commit(
                                User("contributor_1"),
                                CommitMessage("src: sample commit 3"),
                            ),
                            Commit(
                                User("contributor_1"),
                                CommitMessage("src: sample commit 4"),
                            ),
                        ],
                    ),
                    PullRequest(
                        title="Feature 2",
                        number=2,
                        state="closed",
                        merged=True,
                        merged_at=datetime(2023, 2, 1),
                        base=PullRequestBase("main"),
                        user=User("contributor_2"),
                        commits=[
                            Commit(
                                User("contributor_2"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("contributor_2"),
                                CommitMessage("src: sample commit 2"),
                            ),
                            Commit(
                                User("contributor_2"),
                                CommitMessage("src: sample commit 3"),
                            ),
                            Commit(
                                User("contributor_2"),
                                CommitMessage(
                                    "Co-authored-by: old_contrib_coauthor2 <the@email>"
                                ),
                            ),
                            Commit(
                                User("contributor_2"),
                                CommitMessage("src: sample commit 4"),
                            ),
                            Commit(
                                User("contributor_2"),
                                CommitMessage(
                                    "Co-authored-by: old_contrib_coauthor <the@email>"
                                ),
                            ),
                        ],
                    ),
                    PullRequest(
                        title="Feature 3",
                        number=3,
                        state="closed",
                        merged=True,
                        merged_at=datetime(2023, 2, 2),
                        base=PullRequestBase("main"),
                        user=User("contributor_3"),
                        commits=[
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 2"),
                            ),
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 3"),
                            ),
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 4"),
                            ),
                        ],
                    ),
                    PullRequest(
                        title="Feature 4",
                        number=4,
                        state="closed",
                        merged=True,
                        merged_at=datetime(2023, 2, 3),
                        base=PullRequestBase("main"),
                        user=User("contributor_4"),
                        commits=[
                            Commit(
                                User("contributor_4"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("contributor_4"),
                                CommitMessage("src: sample commit 2"),
                            ),
                            Commit(
                                User("contributor_4"),
                                CommitMessage("src: sample commit 3"),
                            ),
                            Commit(
                                User("contributor_4"),
                                CommitMessage("src: sample commit 4"),
                            ),
                        ],
                    ),
                    PullRequest(
                        title="Feature 5",
                        number=5,
                        state="closed",
                        merged=False,
                        merged_at=datetime(2023, 2, 4),
                        base=PullRequestBase("main"),
                        user=User("contributor_3"),
                        commits=[
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 2"),
                            ),
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 3"),
                            ),
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 4"),
                            ),
                        ],
                    ),
                    PullRequest(
                        title="Feature 6",
                        number=12,
                        state="closed",
                        merged=True,
                        merged_at=datetime(2023, 2, 5),
                        base=PullRequestBase("main"),
                        user=User("contributor_2"),
                        commits=[
                            Commit(
                                User("contributor_2"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("contributor_2"),
                                CommitMessage("src: sample commit 2"),
                            ),
                            Commit(
                                User("contributor_2"),
                                CommitMessage("src: sample commit 3"),
                            ),
                            Commit(
                                User("contributor_2"),
                                CommitMessage("src: sample commit 4"),
                            ),
                        ],
                    ),
                    PullRequest(
                        title="Feature 9",
                        number=13,
                        state="closed",
                        merged=True,
                        merged_at=datetime(2023, 5, 2),
                        base=PullRequestBase("main"),
                        user=User("new_contributor_2"),
                        commits=[
                            Commit(
                                User("new_contributor_2"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("new_contributor_2"),
                                CommitMessage("src: sample commit 2"),
                            ),
                            Commit(
                                User("new_contributor_2"),
                                CommitMessage("src: sample commit 3"),
                            ),
                            Commit(
                                User("new_contributor_2"),
                                CommitMessage("src: sample commit 4 "),
                            ),
                            Commit(
                                User("new_contributor_2"),
                                CommitMessage(
                                    "Co-authored-by: new_contributor_coauthor1 <the@email>"
                                ),
                            ),
                        ],
                    ),
                    PullRequest(
                        title="Feature 7",
                        number=14,
                        state="closed",
                        merged=True,
                        merged_at=datetime(2023, 5, 5),
                        base=PullRequestBase("main"),
                        user=User("contributor_3"),
                        commits=[
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 2"),
                            ),
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 3"),
                            ),
                            Commit(
                                User("contributor_3"),
                                CommitMessage("src: sample commit 4 "),
                            ),
                            Commit(
                                User("contributor_3"),
                                CommitMessage(
                                    "Co-authored-by: new_contributor_coauthor2 <the@email>"
                                ),
                            ),
                        ],
                    ),
                    PullRequest(
                        title="Feature 8",
                        number=15,
                        state="closed",
                        merged=True,
                        merged_at=datetime(2023, 5, 1),
                        base=PullRequestBase("main"),
                        user=User("new_contributor_1"),
                        commits=[
                            Commit(
                                User("new_contributor_1"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("new_contributor_1"),
                                CommitMessage("src: sample commit 2"),
                            ),
                            Commit(
                                User("new_contributor_1"),
                                CommitMessage("src: sample commit 3"),
                            ),
                            Commit(
                                User("new_contributor_1"),
                                CommitMessage(
                                    "Co-authored-by: new_contributor_coauthor4 <the@email>"
                                ),
                            ),
                            Commit(
                                User("new_contributor_1"),
                                CommitMessage("src: sample commit 4 "),
                            ),
                            Commit(
                                User("new_contributor_1"),
                                CommitMessage(
                                    "Co-authored-by: new_contributor_coauthor3 <the@email>"
                                ),
                            ),
                        ],
                    ),
                    PullRequest(
                        title="Feature 11",
                        number=16,
                        state="closed",
                        merged=True,
                        merged_at=datetime(2023, 5, 10),
                        base=PullRequestBase("another_branch"),
                        user=User("new_contributor_1"),
                        commits=[
                            Commit(
                                User("new_contributor_1"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("new_contributor_1"),
                                CommitMessage("src: sample commit 2"),
                            ),
                        ],
                    ),
                    PullRequest(
                        title="chore: release v10.0.0",
                        number=17,
                        state="closed",
                        merged=True,
                        merged_at=datetime(2023, 5, 9),
                        base=PullRequestBase("main"),
                        user=User("new_contributor_1"),
                        commits=[
                            Commit(
                                User("new_contributor_1"),
                                CommitMessage("src: sample commit 1"),
                            ),
                            Commit(
                                User("new_contributor_1"),
                                CommitMessage("src: sample commit 2"),
                            ),
                        ],
                    ),
                ],
            )
        )


def test_get_sorted_merged_pulls():
    pulls = RepoStub.get_pulls(state="closed")
    last_release = None

    sorted_merged_pulls = release.get_sorted_merged_pulls(pulls, last_release)

    # Should return all the merged pull requests since there is no previous release
    assert sorted_merged_pulls == sorted(
        [
            pull
            for pull in pulls
            if pull.merged
            and pull.base.ref == "main"
            and not pull.title.startswith("chore: release")
            and not pull.user.login.startswith("github-actions")
        ],
        key=lambda pull: pull.merged_at,
    )


def test_get_last_release():
    releases = RepoStub.get_releases()

    # Should return the latest release
    last_release = release.get_last_release(releases)
    assert last_release.created_at == datetime(2023, 4, 1)

    # Should return None (in case there are no releases yet)
    last_release = release.get_last_release([])
    assert last_release == None


def test_get_old_contributors():
    last_release = release.get_last_release(RepoStub.get_releases())

    old_contributors = release.get_old_contributors(RepoStub.get_pulls(), last_release)

    # Should return contributors until last release, including co-authors
    assert old_contributors == {
        "contributor_2",
        "contributor_3",
        "contributor_4",
        "old_contrib_coauthor",
        "old_contrib_coauthor2",
    }


def test_get_new_contributors():
    last_release = release.get_last_release(RepoStub.get_releases())
    all_pulls = RepoStub.get_pulls()

    # merged pulls after last release
    merged_pulls = release.get_sorted_merged_pulls(all_pulls, last_release)
    old_contributors = release.get_old_contributors(all_pulls, last_release)

    # Should return a List sorted in alphabetic order with only the new contributors since
    # last release
    new_contributors = release.get_new_contributors(old_contributors, merged_pulls)

    assert new_contributors == [
        "new_contributor_1",
        "new_contributor_2",
        "new_contributor_coauthor1",
        "new_contributor_coauthor2",
        "new_contributor_coauthor3",
        "new_contributor_coauthor4",
    ]


def test_whats_changed_md():
    repo_stub = RepoStub()
    last_release = release.get_last_release(RepoStub.get_releases())
    all_pulls = RepoStub.get_pulls()
    # merged pulls after last release
    merged_pulls = release.get_sorted_merged_pulls(all_pulls, last_release)

    whats_changed = release.whats_changed_md(repo_stub.full_name, merged_pulls)

    assert whats_changed == [
        "* Feature 8 by @new_contributor_1, @new_contributor_coauthor3 and @new_contributor_coauthor4 in https://github.com/ada-url/ada/pull/15",
        "* Feature 9 by @new_contributor_2 and @new_contributor_coauthor1 in https://github.com/ada-url/ada/pull/13",
        "* Feature 7 by @contributor_3 and @new_contributor_coauthor2 in https://github.com/ada-url/ada/pull/14",
    ]


def test_new_contributors_md():
    repo_stub = RepoStub()
    last_release = release.get_last_release(RepoStub.get_releases())
    all_pulls = RepoStub.get_pulls()

    merged_pulls = release.get_sorted_merged_pulls(all_pulls, last_release)
    old_contributors = release.get_old_contributors(all_pulls, last_release)
    new_contributors = release.get_new_contributors(old_contributors, merged_pulls)

    # Should return a markdown containing the new contributors and their first contribution
    new_contributors_md = release.new_contributors_md(
        repo_stub.full_name, merged_pulls, new_contributors
    )

    assert new_contributors_md == [
        "* @new_contributor_2 and @new_contributor_coauthor1 made their first contribution in https://github.com/ada-url/ada/pull/13",
        "* @new_contributor_coauthor2 made their first contribution in https://github.com/ada-url/ada/pull/14",
        "* @new_contributor_1, @new_contributor_coauthor3 and @new_contributor_coauthor4 made their first contribution in https://github.com/ada-url/ada/pull/15",
    ]


def test_full_changelog_md():
    repo_stub = RepoStub()
    last_tag = release.get_last_release(repo_stub.get_releases())

    full_changelog = release.full_changelog_md(
        repo_stub.full_name, last_tag.title, "v3.0.0"
    )
    assert (
        full_changelog
        == "**Full Changelog**: https://github.com/ada-url/ada/compare/v1.0.3...v3.0.0"
    )

    full_changelog = release.full_changelog_md(repo_stub.full_name, None, "v3.0.0")
    assert full_changelog is None


def test_contruct_release_notes():
    repo_stub = RepoStub()

    notes = release.contruct_release_notes(repo_stub, "v3.0.0")
    assert (
        notes
        == "## What's changed\n"
        + "* Feature 8 by @new_contributor_1, @new_contributor_coauthor3 and @new_contributor_coauthor4 in https://github.com/ada-url/ada/pull/15\n"
        + "* Feature 9 by @new_contributor_2 and @new_contributor_coauthor1 in https://github.com/ada-url/ada/pull/13\n"
        + "* Feature 7 by @contributor_3 and @new_contributor_coauthor2 in https://github.com/ada-url/ada/pull/14\n"
        + "\n"
        + "## New Contributors\n"
        + "* @new_contributor_2 and @new_contributor_coauthor1 made their first contribution in https://github.com/ada-url/ada/pull/13\n"
        + "* @new_contributor_coauthor2 made their first contribution in https://github.com/ada-url/ada/pull/14\n"
        + "* @new_contributor_1, @new_contributor_coauthor3 and @new_contributor_coauthor4 made their first contribution in https://github.com/ada-url/ada/pull/15\n"
        + "\n"
        + "**Full Changelog**: https://github.com/ada-url/ada/compare/v1.0.3...v3.0.0"
    )


def test_is_valid_tag():
    assert release.is_valid_tag("v1.0.0") is True
    assert release.is_valid_tag("v1.1.1") is True

    assert release.is_valid_tag("v0") is False
    assert release.is_valid_tag("v1.0.0.0") is False
    assert release.is_valid_tag("1.0.0") is False
    assert release.is_valid_tag("1.0.1") is False


def test_multiple_contributors_mention_md():
    contributors = ["contrib1", "contrib2", "contrib3", "contrib4"]

    md_contributors_mention = release.multiple_contributors_mention_md(contributors)
    assert md_contributors_mention == "@contrib1, @contrib2, @contrib3 and @contrib4"

    contributors = ["contrib1"]
    md_contributors_mention = release.multiple_contributors_mention_md(contributors)
    assert md_contributors_mention == "@contrib1"
