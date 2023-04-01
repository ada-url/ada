from release import is_valid_tag


def test_is_valid_tag():
    assert is_valid_tag("v0") is False
    assert is_valid_tag("v1.0.0") is True
