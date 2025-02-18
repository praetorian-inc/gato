import pytest
from gato.models.npfinding import NpFinding
from gato.models.repository import Repository
from unittest.mock import MagicMock, patch

def test_npfinding_init():
    """Test NpFinding class initialization and attribute setting."""
    test_finding = NpFinding(
        rule="test-rule",
        matches=[{"snippet": "test-secret", "provenance": "/path/to/file"}],
        url="https://github.com/test/repo/actions/123",
        workflow_id="12345"
    )

    assert test_finding.rule == "test-rule"
    assert len(test_finding.matches) == 1
    assert test_finding.url == "https://github.com/test/repo/actions/123"
    assert test_finding.workflow_id == "12345"

def test_npfinding_tojson():
    """Test NpFinding JSON serialization."""
    test_finding = NpFinding(
        rule="test-rule",
        matches=[{"snippet": "test-secret", "provenance": "/path/to/file"}],
        url="https://github.com/test/repo/actions/123",
        workflow_id="12345"
    )

    json_data = test_finding.toJSON()
    assert json_data["rule"] == "test-rule"
    assert len(json_data["matches"]) == 1
    assert json_data["URL"] == "https://github.com/test/repo/actions/123"
    assert json_data["Workflow_ID"] == "12345"

def test_repository_artifact_findings():
    """Test Repository class handling of artifact findings."""
    repo_data = {
        "full_name": "test/repo",
        "private": False,
        "permissions": {"admin": True, "push": True, "pull": True},
        "visibility": "public",
        "allow_forking": True
    }

    repo = Repository(repo_data)

    # Test initial state
    assert len(repo.wf_artifact_np_findings) == 0
    assert len(repo.artifact_snippets) == 0

    # Add a finding
    test_finding = NpFinding(
        rule="test-rule",
        matches=[{"snippet": "test-secret", "provenance": "/path/to/file"}],
        url="https://github.com/test/repo/actions/123",
        workflow_id="12345"
    )

    repo.wf_artifact_np_findings.append(test_finding)
    repo.artifact_snippets.add("test-secret")

    # Test after adding finding
    assert len(repo.wf_artifact_np_findings) == 1
    assert len(repo.artifact_snippets) == 1
    assert "test-secret" in repo.artifact_snippets

def test_repository_tojson_with_findings():
    """Test Repository JSON serialization with artifact findings."""
    repo_data = {
        "full_name": "test/repo",
        "private": False,
        "permissions": {"admin": True, "push": True, "pull": True},
        "visibility": "public",
        "allow_forking": True
    }

    repo = Repository(repo_data)

    test_finding = NpFinding(
        rule="test-rule",
        matches=[{"snippet": "test-secret", "provenance": "/path/to/file"}],
        url="https://github.com/test/repo/actions/123",
        workflow_id="12345"
    )

    repo.wf_artifact_np_findings.append(test_finding)

    json_data = repo.toJSON()
    assert "wf_artifact_np_findings" in json_data
    assert len(json_data["wf_artifact_np_findings"]) == 1
    assert json_data["wf_artifact_np_findings"][0]["rule"] == "test-rule"

@patch("gato.models.repository.datetime")
def test_repository_update_time(mock_datetime):
    """Test repository update time with artifact scanning."""
    mock_now = MagicMock()
    mock_datetime.datetime.now.return_value = mock_now

    repo_data = {
        "full_name": "test/repo",
        "private": False,
        "permissions": {"admin": True, "push": True, "pull": True},
        "visibility": "public",
        "allow_forking": True
    }

    repo = Repository(repo_data)
    repo.update_time()

    assert repo.enum_time == mock_now

    json_data = repo.toJSON()
    assert "enum_time" in json_data
