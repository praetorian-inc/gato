import os
import pytest
import pathlib
import logging

from unittest.mock import MagicMock, patch

from gato.github import Api
from gato.cli import Output

logging.root.setLevel(logging.DEBUG)

output = Output(True, False)


@pytest.fixture
def api_access():

    # This PAT is INVALID,
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    yield abstraction_layer


def test_initialize():
    """Test initialization of API abstraction layer.
    """

    # This PAT is INVALID,
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    assert abstraction_layer.pat == test_pat
    assert abstraction_layer.verify_ssl is True


def test_socks(api_access):
    """Test that we can successfully configure a SOCKS proxy.
    """
    # This PAT is INVALID,
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(
        output, test_pat, "2022-11-28", socks_proxy="localhost:9090"
    )

    assert abstraction_layer.proxies['http'] == "socks5://localhost:9090"
    assert abstraction_layer.proxies['https'] == "socks5://localhost:9090"


def test_http_proxy(api_access):
    """Test that we can successfully configure an HTTP proxy.
    """
    # This PAT is INVALID,
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(
        output, test_pat, "2022-11-28", http_proxy="localhost:1080"
    )

    assert abstraction_layer.proxies['http'] == "http://localhost:1080"
    assert abstraction_layer.proxies['https'] == "http://localhost:1080"


@patch("gato.github.api.requests.get")
def test_user_scopes(mock_get):
    """Check user.
    """
    # This PAT is INVALID,
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    mock_result = MagicMock()
    mock_result.configure_mock(
        **{
            "headers.get.return_value": 'repo, admin:org',
            "json.return_value": {'login': 'TestUserName', 'name': 'TestUser'},
            "status_code": 200
        }
    )

    mock_get.return_value = mock_result

    user_info = abstraction_layer.check_user()

    assert user_info['user'] == 'TestUserName'
    assert 'repo' in user_info['scopes']


def test_socks_and_http(api_access):
    """Test initializing API abstraction layer with SOCKS and HTTP proxy,
    which should raise a valueerror.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(ValueError):
        Api(
            output,
            test_pat,
            "2022-11-28",
            socks_proxy="localhost:1090",
            http_proxy="localhost:8080"
        )


@patch("gato.github.api.requests.get")
def test_validate_sso(mock_get):
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    mock_get().status_code = 200

    res = abstraction_layer.validate_sso('testorg', 'testRepo')

    assert res is True


@patch("gato.github.api.requests.get")
def test_validate_sso_fail(mock_get):
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    mock_get().status_code = 403

    res = abstraction_layer.validate_sso('testorg', 'testRepo')

    assert res is False


def test_invalid_pat():
    """Test calling a request with an invalid PAT
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    assert abstraction_layer.check_user() is None


@patch("gato.github.api.requests.delete")
def test_delete_repo(mock_delete):
    """Test forking a repository
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_delete().status_code = 204

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.delete_repository("testOrg/TestRepo")

    assert result is True


@patch("gato.github.api.requests.delete")
def test_delete_fail(mock_delete):
    """Test forking a repository
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_delete().status_code = 403
    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.delete_repository("testOrg/TestRepo")

    assert result is False


@patch("gato.github.api.requests.post")
def test_fork_repository(mock_post):
    """Test fork repo happy path
    """

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 202

    mock_post.return_value.json.return_value = {
        "full_name": "myusername/TestRepo"
    }
    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.fork_repository('testOrg/TestRepo')

    assert result == "myusername/TestRepo"


@patch("gato.github.api.requests.post")
def test_fork_repository_forbid(mock_post):
    """Test repo fork forbidden.
    """

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 403

    mock_post.return_value.json.return_value = {
        "full_name": "myusername/TestRepo"
    }
    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.fork_repository('testOrg/TestRepo')
    assert result is False


@patch("gato.github.api.requests.post")
def test_fork_repository_notfound(mock_post):
    """Test repo fork 404.
    """

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 404

    mock_post.return_value.json.return_value = {
        "full_name": "myusername/TestRepo"
    }
    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.fork_repository('testOrg/TestRepo')
    assert result is False


@patch("gato.github.api.requests.post")
def test_fork_repository_fail(mock_post):
    """Test repo fork failure
    """

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 422

    mock_post.return_value.json.return_value = {
        "full_name": "myusername/TestRepo"
    }
    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.fork_repository('testOrg/TestRepo')
    assert result is False


@patch("gato.github.api.requests.post")
def test_fork_pr(mock_post):
    """Test creating a fork PR
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 201

    mock_post.return_value.json.return_value = {
        "html_url": "https://github.com/testOrg/testRepo/pull/11"
    }

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.create_fork_pr(
        'testOrg/testRepo', 'testuser', 'badBranch', 'develop', 'Test PR Title'
    )

    assert result == "https://github.com/testOrg/testRepo/pull/11"


@patch("gato.github.api.requests.post")
def test_fork_pr_failed(mock_post):
    """Test creating a fork PR
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 401

    mock_post.return_value.json.return_value = {
        "html_url": "https://github.com/testOrg/testRepo/pull/11"
    }

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.create_fork_pr(
        'testOrg/testRepo', 'testuser', 'badBranch', 'develop', 'Test PR Title'
    )

    assert result is None


@patch("gato.github.api.requests.get")
def test_get_repo(mock_get):
    """Test getting repo info.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200
    mock_get.return_value.json.return_value = {"repo1": "fakerepodata"}

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.get_repository('testOrg/TestRepo')

    assert result['repo1'] == "fakerepodata"


@patch("gato.github.api.requests.get")
def test_get_org(mock_get):
    """Test retrievign org info.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200
    mock_get.return_value.json.return_value = {"org1": "fakeorgdata"}

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.get_organization_details('testOrg')

    assert result['org1'] == "fakeorgdata"


@patch("gato.github.api.requests.get")
def test_get_org_notfound(mock_get):
    """Test 404 code when retrieving org info.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 404

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.get_organization_details('testOrg')

    assert result is None


@patch("gato.github.api.requests.get")
def test_check_org_runners(mock_get):
    """Test method to retrieve runners from org.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    mock_get.return_value.json.return_value = {
        "total_count": 5
    }

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.check_org_runners('testOrg')

    assert result == {"total_count": 5}


@patch("gato.github.api.requests.get")
def test_check_org_runners_fail(mock_get):
    """Test method to retrieve runners from org.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 403

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.check_org_runners('testOrg')

    assert result is None


@patch("gato.github.api.requests.get")
def test_check_repo_runners(mock_get):
    """Test method to retrieve runners from org.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    runner_list = [
            {"runnerinfo": "test"},
            {"runnerinfo": "test"},
            {"runnerinfo": "test"},
        ]
    mock_get.return_value.json.return_value = {
        "runners": runner_list
    }

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.get_repo_runners('testOrg/TestRepo')

    assert result == runner_list

    mock_get().status_code = 401

    result = abstraction_layer.get_repo_runners('testOrg/TestRepo')
    assert result is None



@patch("gato.github.api.requests.get")
def test_check_org_repos_invalid(mock_get):
    """Test method to retrieve runners from org.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    with pytest.raises(ValueError):
        abstraction_layer.check_org_repos('testOrg', 'invalid')


@patch("gato.github.api.requests.get")
def test_check_org_repos(mock_get):
    """Test method to retrieve runners from org.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    mock_get.return_value.json.return_value = [
        {"repo1": "fakerepodata"},
        {"repo2": "fakerepodata"},
        {"repo3": "fakerepodata"},
        {"repo4": "fakerepodata"},
        {"repo5": "fakerepodata"},
    ]

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.check_org_repos('testOrg', 'internal')

    assert len(result) == 5


@patch("gato.github.api.requests.get")
def test_check_org(mock_get):
    """Test method to retrieve runners from org.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    mock_get.return_value.json.return_value = [
        {"login": "org1"},
        {"login": "org2"},
        {"login": "org3"},
        {"login": "org4"},
        {"login": "org5"},
    ]

    abstraction_layer = Api(output, test_pat, "2022-11-28")

    result = abstraction_layer.check_organizations()

    assert len(result) == 5
    assert result[0] == "org1"


@patch("gato.github.api.requests.get")
def test_retrieve_run_logs(mock_get):
    """Test retrieving run logs.
    """
    curr_path = pathlib.Path(__file__).parent.resolve()
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    mock_get.return_value.json.return_value = {
        "workflow_runs": [
            {"id": 123, "run_attempt": 1}
        ]
    }

    # Read in the zip file previously downloaded
    with open(os.path.join(curr_path, "files/run_log.zip"), 'rb') as run_log:
        zip_bytes = run_log.read()
        mock_get.return_value.content = zip_bytes

    abstraction_layer = Api(output, test_pat, "2022-11-28")
    logs = abstraction_layer.retrieve_run_logs("testOrg/testRepo")

    assert len(logs) == 1
    assert logs[0]['runner_name'] == 'ghrunner-test'

    logs = abstraction_layer.retrieve_run_logs(
        "testOrg/testRepo", short_circuit=False
    )

    assert len(logs) == 1
    assert logs[0]['runner_name'] == 'ghrunner-test'


@patch("gato.github.api.requests.get")
def test_parse_wf_runs(mock_get):
    """Test retrieving wf run count.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    mock_get.return_value.json.return_value = {
        "total_count": 2
    }

    abstraction_layer = Api(output, test_pat, "2022-11-28")
    wf_count = abstraction_layer.parse_workflow_runs('testOrg/testRepo')

    assert wf_count == 2


@patch("gato.github.api.requests.get")
def test_parse_wf_runs_fail(mock_get):
    """Test 403 code when retrieving wf run count
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 403

    abstraction_layer = Api(output, test_pat, "2022-11-28")
    wf_count = abstraction_layer.parse_workflow_runs('testOrg/testRepo')

    assert wf_count is None


@patch("gato.github.api.requests.get")
def test_get_recent_workflow(mock_get):
    """Test retrieving a recent workflow by sha.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "total_count": 1,
        "workflow_runs": [{
            "id": 15
        }]
    }

    api = Api(output, test_pat, "2022-11-28")
    workflow_id = api.get_recent_workflow('repo', 'sha')

    assert workflow_id == 15


@patch("gato.github.api.requests.get")
def test_get_recent_workflow_missing(mock_get):
    """Test retrieving a missing recent workflow by sha.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "total_count": 0,
        "workflow_runs": []
    }

    api = Api(output, test_pat, "2022-11-28")
    workflow_id = api.get_recent_workflow('repo', 'sha')

    assert workflow_id == 0


@patch("gato.github.api.requests.get")
def test_get_recent_workflow_fail(mock_get):
    """Test failing the retrieval of a recent workflow by sha.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 401

    api = Api(output, test_pat, "2022-11-28")
    workflow_id = api.get_recent_workflow('repo', 'sha')

    assert workflow_id == -1


@patch("gato.github.api.requests.get")
def test_get_workflow_status_queued(mock_get):
    """Test retrieving the status of a workflow.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "status": "queued"
    }

    api = Api(output, test_pat, "2022-11-28")
    assert api.get_workflow_status("repo", 5) == 0


@patch("gato.github.api.requests.get")
def test_get_workflow_status_failed(mock_get):
    """Test retrieving the status of a workflow.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "status": "completed",
        "conclusion": "failure"
    }

    api = Api(output, test_pat, "2022-11-28")
    assert api.get_workflow_status("repo", 5) == -1


@patch("gato.github.api.requests.get")
def test_get_workflow_status_errorr(mock_get):
    """Test retrieving the status of a workflow.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 401

    api = Api(output, test_pat, "2022-11-28")
    assert api.get_workflow_status("repo", 5) == -1


@patch("gato.github.api.requests.delete")
def test_delete_workflow_fail(mock_get):
    """Test retrieving the status of a workflow.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 401

    api = Api(output, test_pat, "2022-11-28")
    assert not api.delete_workflow_run("repo", 5)


@patch("gato.github.api.open")
@patch("gato.github.api.requests.get")
def test_download_workflow_success(mock_get, mock_open):
    """Test retrieving the status of a workflow.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200

    api = Api(output, test_pat, "2022-11-28")
    assert api.download_workflow_logs("repo", 5)


@patch("gato.github.api.open")
@patch("gato.github.api.requests.get")
def test_download_workflow_fail(mock_get, mock_open):
    """Test retrieving the status of a workflow.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 401

    api = Api(output, test_pat, "2022-11-28")
    assert not api.download_workflow_logs("repo", 5)


@patch("gato.github.api.requests.get")
def test_get_repo_branch(mock_get):
    """Test retrieving the existence of a branch.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200

    api = Api(output, test_pat, "2022-11-28")
    assert api.get_repo_branch("repo", "branch") == 1

    mock_get.return_value.status_code = 404
    assert api.get_repo_branch("repo", "branch") == 0

    mock_get.return_value.status_code = 401
    assert api.get_repo_branch("repo", "branch") == -1
