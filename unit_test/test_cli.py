import argparse
import pytest
import os
import pathlib

from unittest import mock
from gato.cli import cli

from gato.util.arg_utils import read_file_and_validate_lines
from gato.util.arg_utils import is_valid_directory


@pytest.fixture(autouse=True)
def mock_settings_env_vars(request):
    with mock.patch.dict(
            os.environ, {
                "GH_TOKEN": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }):
        yield


@mock.patch("gato.git.utils.shutil.which")
def test_cli_git_check(mock_run, capfd):
    """Test case where git is not on path.
    """
    mock_run.return_value = None

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "test"])

    mock_run.assert_called_once()
    out, err = capfd.readouterr()
    assert "not installed" in err


def test_cli_no_gh_token(capfd):
    """Test case where no GH Token is provided
    """
    del os.environ["GH_TOKEN"]

    with pytest.raises(OSError):
        cli.cli(["enumerate", "-t", "test"])

    out, err = capfd.readouterr()
    assert "Please enter" in out


def test_cli_fine_grained_pat(capfd):
    """Test case where an unsupported PAT is provided.
    """
    os.environ["GH_TOKEN"] = "github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()
    assert "not supported" in err


@mock.patch("gato.enumerate.Enumerator.enumerate_organization")
def test_cli_oauth_token(mock_enumerate, capfd):
    """Test case where a GitHub oauth token is provided.
    """
    os.environ["GH_TOKEN"] = "gho_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()

    mock_enumerate.assert_called_once()


@mock.patch("gato.enumerate.Enumerator.enumerate_organization")
def test_cli_old_token(mock_enumerate, capfd):
    """Test case where an old, but still potentially valid GitHub token is provided.
    """
    os.environ["GH_TOKEN"] = "43255147468edf32a206441ad296ce648f44ee32"

    cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()

    mock_enumerate.assert_called_once()


def test_cli_invalid_pat(capfd):
    """Test case where a clearly invalid PAT is provided.
    """
    os.environ["GH_TOKEN"] = "invalid"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()
    assert "malformed" in err


def test_cli_double_proxy(capfd):
    """Test case where conflicing proxies are provided.
    """
    with pytest.raises(SystemExit):
        cli.cli(["-sp", "socks", "-p", "http", "enumerate", "-t", "test"])

    out, err = capfd.readouterr()
    assert "proxy at the same time" in err


def test_attack_bad_args1(capfd):
    """Test attack command without the attack method.
    """

    with pytest.raises(SystemExit):
        cli.cli(["attack", "-t", "test"])

    out, err = capfd.readouterr()
    assert "must select one" in err


def test_attack_bad_args2(capfd):
    """Test attack command with conflicting params.
    """
    curr_path = pathlib.Path(__file__).parent.resolve()

    with pytest.raises(SystemExit):
        cli.cli(["attack", "-t", "test", "-pr",
                 "-f", os.path.join(curr_path, "files/main.yaml"), "-n", "invalid"])

    out, err = capfd.readouterr()
    assert "cannot be used with a custom" in err


def test_attack_invalid_path(capfd):
    """Test attack command with an invalid path.
    """

    with pytest.raises(SystemExit):
        cli.cli(["attack", "-t", "test", "-pr",
                 "-f", "path"])

    out, err = capfd.readouterr()
    assert "argument --custom-file/-f: The file: path does not exist!" in err


def test_repos_file_good():
    """Test that the good file is validated without errors.
    """
    curr_path = pathlib.Path(__file__).parent.resolve()

    res = read_file_and_validate_lines(
        os.path.join(curr_path, "files/test_repos_good.txt"),
        r"[A-Za-z0-9-_.]+\/[A-Za-z0-9-_.]+"
    )

    assert 'someorg/somerepository' in res
    assert 'some_org/some-repo' in res


def test_repos_file_bad(capfd):
    """Test that the good file is validated without errors.
    """
    curr_path = pathlib.Path(__file__).parent.resolve()

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-R",
                 os.path.join(curr_path, "files/test_repos_bad.txt")])

    out, err = capfd.readouterr()

    assert "invalid repository name!" in err


def test_valid_dir():
    """Test that the directory validation function works.
    """
    curr_path = pathlib.Path(__file__).parent.resolve()
    mock_parser = mock.MagicMock()

    res = is_valid_directory(
        mock_parser,
        os.path.join(curr_path, "files/")
    )

    assert res == os.path.join(curr_path, "files/")


def test_invalid_dir(capfd):
    """Test that the directory validation function works.
    """
    curr_path = pathlib.Path(__file__).parent.resolve()
    mock_parser = mock.MagicMock()

    res = is_valid_directory(
        mock_parser,
        os.path.join(curr_path, "invaliddir/")
    )

    assert res is None

    mock_parser.error.assert_called_with(
        "The directory {} does not exist!".format(
                os.path.join(curr_path, "invaliddir/")
            )
        )

@mock.patch("gato.attack.Attacker.fork_pr_attack")
def test_attack_pr(mock_attack):
    """Test attack command using the pr method.
    """
    cli.cli(["attack", "-t", "test", "-pr"])
    mock_attack.assert_called_once()


@mock.patch("gato.attack.Attacker.shell_workflow_attack")
def test_attack_workflow(mock_attack):
    """Test attack command using the workflow method.
    """

    cli.cli(["attack", "-t", "test", "-w"])
    mock_attack.assert_called_once()


@mock.patch("os.path.isdir")
def test_enum_bad_args1(mock_dircheck, capfd):
    """Test enum command with invalid output location.
    """
    mock_dircheck.return_value = False

    with pytest.raises(SystemExit):
        cli.cli(["enum", "-o", "invalid"])

    out, err = capfd.readouterr()
    assert "--output-yaml/-o: The directory: invalid does not exist!" in err


def test_enum_bad_args2(capfd):
    """Test enum command without a type selection.
    """
    with pytest.raises(SystemExit):
        cli.cli(["enum"])

    out, err = capfd.readouterr()
    assert "type was specified" in err


def test_enum_bad_args3(capfd):
    """Test enum command with multiple type selections.
    """
    with pytest.raises(SystemExit):
        cli.cli(["enum", "-t", "test", "-r",  "testorg/test2"])

    out, err = capfd.readouterr()
    assert "select one enumeration" in err


def test_enum_bad_args4(capfd):
    """Test enum command with conflicting params.
    """
    with pytest.raises(SystemExit):
        cli.cli(["enum", "-t", "test", "-sc", "-o", "test"])

    out, err = capfd.readouterr()
    assert "if cloning is not" in err


@mock.patch("gato.enumerate.Enumerator.self_enumeration")
def test_enum_self(mock_enumerate):
    """Test enum command using the self enumerattion.
    """

    cli.cli(["enum", "-s"])
    mock_enumerate.assert_called_once()


@mock.patch("gato.enumerate.Enumerator.enumerate_organization")
def test_enum_org(mock_enumerate):
    """Test enum command using the organization enumerattion.
    """

    cli.cli(["enum", "-t", "test"])
    mock_enumerate.assert_called_once()


@mock.patch("gato.enumerate.Enumerator.enumerate_repos")
@mock.patch("gato.util.read_file_and_validate_lines")
def test_enum_repos(mock_read, mock_enumerate):
    """Test enum command using the repo list.
    """
    curr_path = pathlib.Path(__file__).parent.resolve()
    mock_read.return_value = "repos"

    cli.cli(
        ["enum", "-R", os.path.join(curr_path, "files/test_repos_good.txt")]
    )
    mock_read.assert_called_once()
    mock_enumerate.assert_called_once()


@mock.patch("gato.enumerate.Enumerator.enumerate_repo_only")
def test_enum_repo(mock_enumerate):
    """Test enum command using the organization enumerattion.
    """
    cli.cli(["enum", "-r", "testorg/testrepo"])
    mock_enumerate.assert_called_once()


@mock.patch("gato.search.Searcher.use_search_api")
def test_search(mock_search):
    """Test search command
    """

    cli.cli(["search", "-t", "test"])
    mock_search.assert_called_once()


@mock.patch("gato.git.version_check")
def test_git_version_old(git_version, capfd):
    """Test the handling of the git version check
    """
    git_version.return_value = "2.25"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "someorg"])
    out, err = capfd.readouterr()

    assert " This tool requires a 'git' version of at least 2.27" in err

@mock.patch("gato.git.path_check")
@mock.patch("gato.git.version_check")
def test_invalid_timeout(git_version, git_bin, capfd):
    """Test invalid timeout value.
    """
    git_version.return_value = "2.36"
    git_bin.return_value = "/usr/local/bin/git"

    with pytest.raises(SystemExit):
        cli.cli(
            [
                "a", "--timeout", "foobar", "-t",
                "someorg/somerepo", "--workflow"
            ]
        )

    out, err = capfd.readouterr()

    assert "invalid int value: 'foobar'" in err

def test_long_repo_name(capfd):
    """Test enum command using name that is too long.
    """

    repo_name = "Org/" + "A" * 80

    with pytest.raises(SystemExit):
        cli.cli(["enum", "-r", repo_name])

    out, err = capfd.readouterr()

    assert "The maximum length is 79 characters!" in err


def test_invalid_repo_name(capfd):
    """Test enum command using invalid full repo name.
    """
    with pytest.raises(SystemExit):
        cli.cli(["enum", "-r", "RepoWithoutOrg"])

    out, err = capfd.readouterr()

    assert "argument --repository/-r: The argument" \
           " is not in the valid format!" in err


@mock.patch("gato.util.arg_utils.os.access")
def test_unreadable_file(mock_access, capfd):
    """Test enum command unreadable file.
    """
    curr_path = pathlib.Path(__file__).parent.resolve()

    mock_access.return_value = False

    with pytest.raises(SystemExit):
        cli.cli(
            ["enum", "-R", os.path.join(curr_path, "files/bad_dir/bad_file")]
        )

    out, err = capfd.readouterr()

    assert " is not readable" in err

@mock.patch("gato.util.arg_utils.os.access")
def test_unwritable_dir(mock_access, capfd):
    """Test enum command unwriable dir.
    """
    curr_path = pathlib.Path(__file__).parent.resolve()

    mock_access.return_value = False

    with pytest.raises(SystemExit):
        cli.cli(
            ["enum", "-r", 'testOrg/testRepo', '-o',
             os.path.join(curr_path, 'files/bad_dir')]
        )

    out, err = capfd.readouterr()

    assert " is not writeable" in err

@mock.patch("gato.git.utils.shutil.which")
@mock.patch("gato.git.utils.subprocess.run")
def test_cli_git_check_invalid(mock_run, mock_shutil, capfd):
    """Test case where git is not on path.
    """
    mock_run.return_value.returncode = 1
    mock_shutil.return_value = "/usr/local/bin/git"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "someorg"])

    mock_run.assert_called_once()
    out, err = capfd.readouterr()
    assert "'git --version' returned unexpected output!" in err
