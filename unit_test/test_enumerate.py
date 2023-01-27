import os
import pathlib
import pytest
import json
import re

from unittest.mock import patch

from gato.models.repository import Repository
from gato.enumerate import Enumerator

TEST_REPO_DATA = None
TEST_WORKFLOW_YML = None


@pytest.fixture(scope="session", autouse=True)
def load_test_files(request):
    global TEST_REPO_DATA
    global TEST_WORKFLOW_YML
    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/example_repo.json")
    test_wf_path = os.path.join(curr_path, 'files/main.yaml')

    with open(test_repo_path, 'r') as repo_data:
        TEST_REPO_DATA = json.load(repo_data)

    with open(test_wf_path, 'r') as wf_data:
        TEST_WORKFLOW_YML = wf_data.read()


# From https://stackoverflow.com/questions/14693701/
# how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
def escape_ansi(line):
    ansi_escape = re.compile(
        r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]',
        re.MULTILINE
    )
    return ansi_escape.sub('', line)


def test_init():
    """Test constructor for enumerator.
    """

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_clones=False,
        output_yaml=True,
        skip_log=False,
    )

    assert gh_enumeration_runner.http_proxy == "localhost:8080"

@patch("gato.enumerate.enumerate.Api")
def test_self_enumerate(mock_api, capsys):
    """Test constructor for enumerator.
    """

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_clones=False,
        output_yaml=True,
        skip_log=False,
    )

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.check_organizations.return_value = []

    gh_enumeration_runner.self_enumeration()

    captured = capsys.readouterr()

    print_output = captured.out
    assert "The user testUser belongs to 0 organizations!" in escape_ansi(
        print_output
    )


@patch("gato.enumerate.enumerate.Api")
def test_enumerate_repo(mock_api, capsys):
    """Test constructor for enumerator.
    """

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_clones=False,
        output_yaml=True,
        skip_log=False,
    )

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.retrieve_run_logs.return_value = [
        {"machine_name": "unittest1", "runner_name": "much_unit_such_test"}
    ]

    repo_data = json.loads(json.dumps(TEST_REPO_DATA))
    test_repo = Repository(repo_data)

    gh_enumeration_runner.enumerate_repository(
        test_repo, clone=False
    )

    captured = capsys.readouterr()

    print_output = captured.out
    assert "The runner name was: much_unit_such_test" in escape_ansi(
        print_output
    )

    assert "the machine name was unittest1" in escape_ansi(
        print_output
    )


@patch("gato.enumerate.enumerate.Api")
def test_enumerate_repo_admin(mock_api, capsys):
    """Test constructor for enumerator.
    """

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_clones=False,
        output_yaml=True,
        skip_log=False,
    )

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.retrieve_run_logs.return_value = [
        {"machine_name": "unittest1", "runner_name": "much_unit_such_test"}
    ]

    repo_data = json.loads(json.dumps(TEST_REPO_DATA))
    repo_data['permissions']['admin'] = True
    test_repo = Repository(repo_data)

    gh_enumeration_runner.enumerate_repository(
        test_repo, clone=False
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert "The user is an administrator on the" in escape_ansi(
        print_output
    )


@patch("gato.enumerate.enumerate.Api")
def test_enumerate_repo_admin_no_wf(mock_api, capsys):
    """Test constructor for enumerator.
    """

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_clones=False,
        output_yaml=True,
        skip_log=False,
    )

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo']
    }

    mock_api.return_value.retrieve_run_logs.return_value = [
        {"machine_name": "unittest1", "runner_name": "much_unit_such_test"}
    ]

    repo_data = json.loads(json.dumps(TEST_REPO_DATA))

    repo_data['permissions']['admin'] = True
    test_repo = Repository(repo_data)

    gh_enumeration_runner.enumerate_repository(
        test_repo, clone=False
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert " is public this token can be used to approve a" in escape_ansi(
        print_output
    )


@patch("gato.enumerate.enumerate.Api")
def test_enumerate_repo_no_wf_no_admin(mock_api, capsys):
    """Test constructor for enumerator.
    """

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_clones=False,
        output_yaml=True,
        skip_log=False,
    )

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo']
    }

    mock_api.return_value.retrieve_run_logs.return_value = [
        {"machine_name": "unittest1", "runner_name": "much_unit_such_test"}
    ]

    repo_data = json.loads(json.dumps(TEST_REPO_DATA))
    repo_data['permissions']['admin'] = False
    test_repo = Repository(repo_data)

    gh_enumeration_runner.enumerate_repository(
        test_repo, clone=False
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert " scope, which means an existing workflow trigger must" in \
        escape_ansi(print_output)


@patch("gato.enumerate.enumerate.Api")
def test_enumerate_repo_no_wf_maintain(mock_api, capsys):
    """Test constructor for enumerator.
    """

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_clones=False,
        output_yaml=True,
        skip_log=False,
    )

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.retrieve_run_logs.return_value = [
        {"machine_name": "unittest1", "runner_name": "much_unit_such_test"}
    ]

    repo_data = json.loads(json.dumps(TEST_REPO_DATA))

    repo_data['permissions']['maintain'] = True
    test_repo = Repository(repo_data)

    gh_enumeration_runner.enumerate_repository(
        test_repo, clone=False
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert " The user is a maintainer on the" in escape_ansi(
        print_output
    )


@patch("gato.enumerate.enumerate.WorkflowParser.output")
@patch("gato.enumerate.enumerate.Git")
def test_clone_enumeration(mock_git, mock_wfout):
    """Test enumerating via parsing workflow files.
    """

    mock_wfout.return_value = True

    mock_git().extract_workflow_ymls.return_value = [
        ('main.yml', TEST_WORKFLOW_YML)
    ]

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=False,
        output_yaml="files/",
        skip_log=False,
    )

    test_repo = Repository(TEST_REPO_DATA)

    self_hosted = gh_enumeration_runner._Enumerator__perform_clone_enumeration(
        test_repo
    )

    assert self_hosted is True
    mock_wfout.assert_called_once()


@patch("gato.enumerate.enumerate.WorkflowParser.output")
@patch("gato.enumerate.enumerate.Git")
def test_clone_enumeration_writeerror(mock_git, mock_wfout):
    """Test enumerating via parsing workflow files.
    """

    mock_wfout.return_value = False

    mock_git().extract_workflow_ymls.return_value = [
        ('main.yml', TEST_WORKFLOW_YML)
    ]

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=False,
        output_yaml="files/bad_dir",
        skip_log=False,
    )

    test_repo = Repository(TEST_REPO_DATA)

    self_hosted = gh_enumeration_runner._Enumerator__perform_clone_enumeration(
        test_repo
    )

    assert self_hosted is True
    mock_wfout.assert_called_once()


@patch("gato.enumerate.enumerate.Git")
def test_clone_enumeration_parse_error(mock_git):
    """Test enumerating via parsing workflow files.
    """
    mock_git().extract_workflow_ymls.return_value = [
        ('main.yml', "FOOBARBAZ")
    ]

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=False,
        output_yaml=False,
        skip_log=False,
    )

    test_repo = Repository(TEST_REPO_DATA)

    self_hosted = gh_enumeration_runner._Enumerator__perform_clone_enumeration(
        test_repo
    )

    assert self_hosted is False


@patch("gato.enumerate.enumerate.Git")
def test_clone_enumeration_none(mock_git):
    mock_git().extract_workflow_ymls.return_value = []

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=False,
        output_yaml=False,
        skip_log=False,
    )

    test_repo = Repository(TEST_REPO_DATA)

    self_hosted = gh_enumeration_runner._Enumerator__perform_clone_enumeration(
        test_repo
    )

    assert self_hosted is False


def test_print_runners(capfd):

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=False,
        output_yaml=False,
        skip_log=False,
    )

    runners_json = """
    {
    "total_count":1,
    "runners":[
        {
            "id":21,
            "name":"ghrunner-test",
            "os":"Linux",
            "status":"online",
            "busy":false,
            "labels":[
                {
                "id":1,
                "name":"self-hosted",
                "type":"read-only"
                },
                {
                "id":2,
                "name":"Linux",
                "type":"read-only"
                },
                {
                "id":3,
                "name":"X64",
                "type":"read-only"
                }
            ]
        }
    ]
    }
    """

    gh_enumeration_runner._Enumerator__print_runner_info(
        json.loads(runners_json)
    )

    out, err = capfd.readouterr()

    assert "The runner has the following labels: self-hosted, Linux, X64" in \
        escape_ansi(out)


@patch("gato.enumerate.enumerate.Api")
def test_assemble_repo_list(mock_api):

    mock_api().check_org_repos.return_value = [TEST_REPO_DATA]

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=False,
        output_yaml=False,
        skip_log=False,
    )

    repos = gh_enumeration_runner._Enumerator__assemble_repo_list(
        "testOrg", ['public']
    )

    assert len(repos) == 1
    assert repos[0].is_public() is True


@patch("gato.enumerate.enumerate.Api")
def test_enum_repo(mock_api, capfd):

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.get_repository.return_value = TEST_REPO_DATA

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=True,
        output_yaml=False,
        skip_log=True,
    )

    gh_enumeration_runner.enumerate_repo_only("octocat/Hello-World")
    out, err = capfd.readouterr()
    assert "Enumerating: octocat/Hello-World" in escape_ansi(out)
    mock_api.return_value.get_repository.assert_called_once_with(
        "octocat/Hello-World"
    )


@patch("gato.enumerate.enumerate.Api")
def test_enum_repo_runner(mock_api, capfd):

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.get_repo_runners.return_value = [
        {
            'id': 2,
            'name': '17e749a1b008',
            'os': 'Linux',
            'status': 'offline',
            'busy': False,
            'labels': [
                {
                    'id': 1,
                    'name': 'self-hosted',
                    'type': 'read-only'
                },
                {
                    'id': 2,
                    'name': 'Linux',
                    'type': 'read-only',
                },
                {
                    'id': 3,
                    'name': 'X64',
                    'type': 'read-only',
                }
            ]
        }
    ]

    test_repodata = TEST_REPO_DATA.copy()

    test_repodata["permissions"]['admin'] = True

    mock_api.return_value.get_repository.return_value = test_repodata

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=True,
        output_yaml=False,
        skip_log=True,
    )

    gh_enumeration_runner.enumerate_repo_only("octocat/Hello-World")
    out, err = capfd.readouterr()

    escaped_output = escape_ansi(out)

    assert "The repository has 1 repo-level self-hosted runners!" in \
        escaped_output

    assert "[!] The user is an administrator on the repository!" in \
        escaped_output

    assert "The runner has the following labels: self-hosted, Linux, X64!" in \
        escaped_output


@patch("gato.enumerate.enumerate.Api")
def test_enum_repos(mock_api, capfd):

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.get_repository.return_value = TEST_REPO_DATA

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=True,
        output_yaml=False,
        skip_log=True,
    )

    gh_enumeration_runner.enumerate_repos(["octocat/Hello-World"])
    out, _ = capfd.readouterr()
    assert "Enumerating: octocat/Hello-World" in escape_ansi(out)
    mock_api.return_value.get_repository.assert_called_once_with(
        "octocat/Hello-World"
    )


@patch("gato.enumerate.enumerate.Api")
def test_enum_repos_empty(mock_api, capfd):

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.get_repository.return_value = TEST_REPO_DATA

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=True,
        output_yaml=False,
        skip_log=True,
    )

    gh_enumeration_runner.enumerate_repos([])
    out, _ = capfd.readouterr()
    assert "The list of repositories was empty!" in escape_ansi(out)
    mock_api.return_value.get_repository.assert_not_called()


@patch("gato.enumerate.enumerate.Api")
def test_bad_token(mock_api):

    gh_enumeration_runner = Enumerator(
        "ghp_BADTOKEN",
        socks_proxy=None,
        http_proxy=None,
        skip_clones=True,
        output_yaml=False,
        skip_log=True,
    )

    mock_api.return_value.check_user.return_value = None

    val = gh_enumeration_runner.self_enumeration()

    assert val is False
