from .. import versions
import os


def test_update_cmakelists_version():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sample_path = f"{current_dir}/samples/cmakelists.txt"
    sample_expected_path = f"{current_dir}/samples/cmakelists_expected.txt"

    versions.update_cmakelists_version("2.0.0", sample_path)

    with open(sample_path, "r") as cmake:
        given = cmake.read()

    with open(sample_expected_path, "r") as cmake_expected:
        expected = cmake_expected.read()

    assert given == expected
    versions.update_cmakelists_version("1.0.0", sample_path)  # cleanup


def test_update_ada_version_h():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sample_path = f"{current_dir}/samples/ada_version_h.txt"
    sample_expected_path = f"{current_dir}/samples/ada_version_h_expected.txt"

    versions.update_ada_version_h("2.0.0", sample_path)

    with open(sample_path, "r") as ada_version_h:
        given = ada_version_h.read()

    with open(sample_expected_path, "r") as ada_version_h_expected:
        expected = ada_version_h_expected.read()

    assert given == expected
    versions.update_ada_version_h("1.0.0", sample_path)  # cleanup


def test_update_doxygen_version():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sample_path = f"{current_dir}/samples/doxygen.txt"
    sample_expected_path = f"{current_dir}/samples/doxygen_expected.txt"

    versions.update_doxygen_version("2.0.0", sample_path)

    with open(sample_path, "r") as doxygen:
        given = doxygen.read()

    with open(sample_expected_path, "r") as doxygen_expected:
        expected = doxygen_expected.read()

    assert given == expected
    versions.update_ada_version_h("1.0.0", sample_path)  # cleanup
