from .. import release
from datetime import datetime
from typing import NamedTuple


class Release(NamedTuple):
    title: str
    created_at: datetime


class User(NamedTuple):
    login: str


class CommitMessage(NamedTuple):
    message: str


class Commit(NamedTuple):
    author: User
    commit: CommitMessage


class PullRequestBase(NamedTuple):
    ref: str


class PullRequest(NamedTuple):
    title: str
    number: int
    state: str
    base: PullRequestBase
    merged: bool
    merged_at: datetime
    user: User
    commits: list[Commit]

    def get_commits(self) -> list[Commit]:
        return self.commits


class RepoStub:
    def __init__(self) -> None:
        self.created_at = datetime(2023, 1, 1)
        self.full_name = 'ada-url/ada'

    @staticmethod
    def get_releases() -> list[Release]:
        return [
            Release('v1.0.1', datetime(2023, 2, 1)),
            Release('v1.0.3', datetime(2023, 4, 1)),
            Release('v1.0.2', datetime(2023, 3, 1)),
        ]

    @staticmethod
    def get_pulls(state: str = 'closed') -> list[PullRequest]:
        return list(
            filter(
                lambda pull: pull.state == state,
                [
                    PullRequest(
                        title='Feature 1',
                        number=1,
                        state='open',
                        merged=False,
                        base=PullRequestBase('main'),
                        merged_at=datetime(2023, 2, 2),
                        user=User('contributor_1'),
                        commits=[
                            Commit(
                                User('contributor_1'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('contributor_1'),
                                CommitMessage('src: sample commit 2'),
                            ),
                            Commit(
                                User('contributor_1'),
                                CommitMessage('src: sample commit 3'),
                            ),
                            Commit(
                                User('contributor_1'),
                                CommitMessage('src: sample commit 4'),
                            ),
                        ],
                    ),
                    PullRequest(
                        title='Feature 2',
                        number=2,
                        state='closed',
                        merged=True,
                        merged_at=datetime(2023, 2, 1),
                        base=PullRequestBase('main'),
                        user=User('contributor_2'),
                        commits=[
                            Commit(
                                User('contributor_2'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('contributor_2'),
                                CommitMessage('src: sample commit 2'),
                            ),
                            Commit(
                                User('contributor_2'),
                                CommitMessage('src: sample commit 3'),
                            ),
                            Commit(
                                User('contributor_2'),
                                CommitMessage('Co-authored-by: old_contrib_coauthor2 <the@email>'),
                            ),
                            Commit(
                                User('contributor_2'),
                                CommitMessage('src: sample commit 4'),
                            ),
                            Commit(
                                User('contributor_2'),
                                CommitMessage('Co-authored-by: old_contrib_coauthor <the@email>'),
                            ),
                        ],
                    ),
                    PullRequest(
                        title='Feature 3',
                        number=3,
                        state='closed',
                        merged=True,
                        merged_at=datetime(2023, 2, 2),
                        base=PullRequestBase('main'),
                        user=User('contributor_3'),
                        commits=[
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 2'),
                            ),
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 3'),
                            ),
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 4'),
                            ),
                        ],
                    ),
                    PullRequest(
                        title='Feature 4',
                        number=4,
                        state='closed',
                        merged=True,
                        merged_at=datetime(2023, 2, 3),
                        base=PullRequestBase('main'),
                        user=User('contributor_4'),
                        commits=[
                            Commit(
                                User('contributor_4'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('contributor_4'),
                                CommitMessage('src: sample commit 2'),
                            ),
                            Commit(
                                User('contributor_4'),
                                CommitMessage('src: sample commit 3'),
                            ),
                            Commit(
                                User('contributor_4'),
                                CommitMessage('src: sample commit 4'),
                            ),
                        ],
                    ),
                    PullRequest(
                        title='Feature 5',
                        number=5,
                        state='closed',
                        merged=False,
                        merged_at=datetime(2023, 2, 4),
                        base=PullRequestBase('main'),
                        user=User('contributor_3'),
                        commits=[
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 2'),
                            ),
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 3'),
                            ),
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 4'),
                            ),
                        ],
                    ),
                    PullRequest(
                        title='Feature 6',
                        number=12,
                        state='closed',
                        merged=True,
                        merged_at=datetime(2023, 2, 5),
                        base=PullRequestBase('main'),
                        user=User('contributor_2'),
                        commits=[
                            Commit(
                                User('contributor_2'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('contributor_2'),
                                CommitMessage('src: sample commit 2'),
                            ),
                            Commit(
                                User('contributor_2'),
                                CommitMessage('src: sample commit 3'),
                            ),
                            Commit(
                                User('contributor_2'),
                                CommitMessage('src: sample commit 4'),
                            ),
                        ],
                    ),
                    PullRequest(
                        title='Feature 9',
                        number=13,
                        state='closed',
                        merged=True,
                        merged_at=datetime(2023, 5, 2),
                        base=PullRequestBase('main'),
                        user=User('new_contributor_2'),
                        commits=[
                            Commit(
                                User('new_contributor_2'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('new_contributor_2'),
                                CommitMessage('src: sample commit 2'),
                            ),
                            Commit(
                                User('new_contributor_2'),
                                CommitMessage('src: sample commit 3'),
                            ),
                            Commit(
                                User('new_contributor_2'),
                                CommitMessage('src: sample commit 4 '),
                            ),
                            Commit(
                                User('new_contributor_2'),
                                CommitMessage('Co-authored-by: new_contributor_coauthor1 <the@email>'),
                            ),
                        ],
                    ),
                    PullRequest(
                        title='Feature 7',
                        number=14,
                        state='closed',
                        merged=True,
                        merged_at=datetime(2023, 5, 5),
                        base=PullRequestBase('main'),
                        user=User('contributor_3'),
                        commits=[
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 2'),
                            ),
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 3'),
                            ),
                            Commit(
                                User('contributor_3'),
                                CommitMessage('src: sample commit 4 '),
                            ),
                            Commit(
                                User('contributor_3'),
                                CommitMessage('Co-authored-by: new_contributor_coauthor2 <the@email>'),
                            ),
                        ],
                    ),
                    PullRequest(
                        title='Feature 8',
                        number=15,
                        state='closed',
                        merged=True,
                        merged_at=datetime(2023, 5, 1),
                        base=PullRequestBase('main'),
                        user=User('new_contributor_1'),
                        commits=[
                            Commit(
                                User('new_contributor_1'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('new_contributor_1'),
                                CommitMessage('src: sample commit 2'),
                            ),
                            Commit(
                                User('new_contributor_1'),
                                CommitMessage('src: sample commit 3'),
                            ),
                            Commit(
                                User('new_contributor_1'),
                                CommitMessage('Co-authored-by: new_contributor_coauthor4 <the@email>'),
                            ),
                            Commit(
                                User('new_contributor_1'),
                                CommitMessage('src: sample commit 4 '),
                            ),
                            Commit(
                                User('new_contributor_1'),
                                CommitMessage('Co-authored-by: new_contributor_coauthor3 <the@email>'),
                            ),
                        ],
                    ),
                    PullRequest(
                        title='Feature 11',
                        number=16,
                        state='closed',
                        merged=True,
                        merged_at=datetime(2023, 5, 10),
                        base=PullRequestBase('another_branch'),
                        user=User('new_contributor_1'),
                        commits=[
                            Commit(
                                User('new_contributor_1'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('new_contributor_1'),
                                CommitMessage('src: sample commit 2'),
                            ),
                        ],
                    ),
                    PullRequest(
                        title='chore: release v10.0.0',
                        number=17,
                        state='closed',
                        merged=True,
                        merged_at=datetime(2023, 5, 9),
                        base=PullRequestBase('main'),
                        user=User('new_contributor_1'),
                        commits=[
                            Commit(
                                User('new_contributor_1'),
                                CommitMessage('src: sample commit 1'),
                            ),
                            Commit(
                                User('new_contributor_1'),
                                CommitMessage('src: sample commit 2'),
                            ),
                        ],
                    ),
                ],
            )
        )


def test_is_valid_tag() -> None:
    assert release.is_valid_tag('v1.0.0') is True
    assert release.is_valid_tag('v1.1.1') is True

    assert release.is_valid_tag('v0') is False
    assert release.is_valid_tag('v1.0.0.0') is False
    assert release.is_valid_tag('1.0.0') is False
    assert release.is_valid_tag('1.0.1') is False
