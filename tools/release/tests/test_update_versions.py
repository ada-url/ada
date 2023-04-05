import update_versions


def test_update_cmakelists_version():
    sample_path = "./sample_cmakelists.txt"
    sample_expected_path = "./sample_cmakelists_expected.txt"

    update_versions.update_cmakelists_version("2.0.0", "./sample_cmakelists.txt")

    with open(sample_path, 'r') as sample_cmake:
        given = sample_cmake.read()

    with open(sample_expected_path, 'r') as sample_cmake_expected:
        expected = sample_cmake_expected.read()

    assert given == expected
