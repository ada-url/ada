from .. import release
from datetime import datetime
from collections import namedtuple

Release = namedtuple("Release", ["title", "created_at"])
PullRequest = namedtuple(
    "PullRequest", ["title", "number", "state", "merged", "merged_at", "user"]
)
User = namedtuple("User", ["login"])


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
        return filter(
            lambda pull: pull.state == state,
            [
                PullRequest(
                    "Feature 1",
                    10,
                    "open",
                    False,
                    datetime(2023, 2, 2),
                    User("contr_1"),
                ),
                PullRequest(
                    "Refactoring 1",
                    11,
                    "closed",
                    True,
                    datetime(2023, 2, 3),
                    User("contr_2"),
                ),
                PullRequest(
                    "Feature 2",
                    12,
                    "closed",
                    True,
                    datetime(2023, 5, 4),
                    User("new_contr_1"),
                ),
                PullRequest(
                    "Feature 10",
                    22,
                    "closed",
                    True,
                    datetime(2023, 5, 11),
                    User("contr_2"),
                ),
                PullRequest(
                    "Feature 3",
                    13,
                    "closed",
                    False,
                    datetime(2023, 5, 9),
                    User("contr_3"),
                ),
                PullRequest(
                    "Refactoring",
                    15,
                    "closed",
                    True,
                    datetime(2023, 5, 10),
                    User("new_contr_2"),
                ),
                PullRequest(
                    "Feature 10",
                    142,
                    "open",
                    False,
                    datetime(2023, 5, 10),
                    User("contr_3"),
                ),
            ],
        )


def test_get_last_release(mocker):
    repo_stub = RepoStub()

    # Should return the latest release
    last_release = release.get_last_release(repo_stub)
    assert last_release.created_at == datetime(2023, 4, 1)

    # Should return None (in case there are no releases yet)
    mocker.patch.object(repo_stub, "get_releases", return_value=[])
    last_release = release.get_last_release(repo_stub)
    assert last_release == None


def test_get_release_merged_pulls():
    repo_stub = RepoStub()
    last_release = release.get_last_release(repo_stub)

    # Should return the merged pull requests after the last release.
    # In other words, the ones that will be entering the next release.
    merged_pulls = release.get_release_merged_pulls(repo_stub, last_release)
    assert merged_pulls == [
        PullRequest(
            "Feature 2",
            12,
            "closed",
            True,
            datetime(2023, 5, 4),
            User("new_contr_1"),
        ),
        PullRequest(
            "Refactoring",
            15,
            "closed",
            True,
            datetime(2023, 5, 10),
            User("new_contr_2"),
        ),
        PullRequest(
            "Feature 10",
            22,
            "closed",
            True,
            datetime(2023, 5, 11),
            User("contr_2"),
        ),
    ]


def test_get_new_contributors():
    repo_stub = RepoStub()
    last_release = release.get_last_release(repo_stub)

    # Should return a Set with only the new contributors since last release
    new_contributors = release.get_new_contributors(repo_stub, last_release)
    assert new_contributors == {
        "new_contr_1": [
            PullRequest(
                "Feature 2",
                12,
                "closed",
                True,
                datetime(2023, 5, 4),
                User("new_contr_1"),
            )
        ],
        "new_contr_2": [
            PullRequest(
                "Refactoring",
                15,
                "closed",
                True,
                datetime(2023, 5, 10),
                User("new_contr_2"),
            )
        ],
    }


def test_whats_changed_md():
    repo_stub = RepoStub()
    last_release = release.get_last_release(repo_stub)

    # Should return a set with the markdown lines containing the merged pull requests
    # for the next release
    whats_changed = release.whats_changed_md(repo_stub, last_release)
    assert whats_changed == [
        "* Feature 2 by @new_contr_1 in https://github.com/ada-url/ada/pull/12",
        "* Refactoring by @new_contr_2 in https://github.com/ada-url/ada/pull/15",
        "* Feature 10 by @contr_2 in https://github.com/ada-url/ada/pull/22",
    ]


def test_new_contributors_md():
    repo_stub = RepoStub()
    last_release = release.get_last_release(repo_stub)

    # Should return a set with the markdown lines containing the new contributors
    # for the next release
    new_contributors_md = release.new_contributors_md(repo_stub, last_release)
    assert new_contributors_md == [
        "* @new_contr_1 made their first contribution in https://github.com/ada-url/ada/pull/12",
        "* @new_contr_2 made their first contribution in https://github.com/ada-url/ada/pull/15",
    ]


def test_full_changelog_md():
    repo_stub = RepoStub()
    last_tag = release.get_last_release(repo_stub)

    full_changelog = release.full_changelog_md(
        repo_stub.full_name, last_tag.title, "v3.0.0"
    )
    assert (
        full_changelog
        == "**Full Changelog**: https://github.com/ada-url/ada/compare/v1.0.3...v3.0.0"
    )


def test_contruct_release_notes():
    repo_stub = RepoStub()

    notes = release.contruct_release_notes(repo_stub, "v3.0.0")
    assert (
        notes
        == "## What's Changed\n"
        + "* Feature 2 by @new_contr_1 in https://github.com/ada-url/ada/pull/12\n"
        + "* Refactoring by @new_contr_2 in https://github.com/ada-url/ada/pull/15\n"
        + "* Feature 10 by @contr_2 in https://github.com/ada-url/ada/pull/22\n"
        + "\n"
        + "## New Contributors\n"
        + "* @new_contr_1 made their first contribution in https://github.com/ada-url/ada/pull/12\n"
        + "* @new_contr_2 made their first contribution in https://github.com/ada-url/ada/pull/15\n"
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
