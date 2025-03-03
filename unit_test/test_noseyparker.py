import pytest
import os
import json
import tempfile
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path

from gato.artifact_secrets_scanner.noseyparker import NPHandler
from gato.models.repository import Repository


# Sample Nosey Parker JSON output for testing
SAMPLE_NP_JSON = '''
[
  {
    "rule_name": "aws-access-key-id",
    "matches": [
      {
        "path": "test/file1.txt",
        "snippet": {
          "matching": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        },
        "provenance": [
          {
            "path": "test/file1.txt"
          }
        ]
      }
    ]
  },
  {
    "rule_name": "github-personal-access-token",
    "matches": [
      {
        "path": "test/file2.txt",
        "snippet": {
          "matching": "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        },
        "provenance": [
          {
            "path": "test/file2.txt"
          }
        ]
      }
    ]
  }
]
'''


@pytest.fixture
def mock_repo():
    """Create a mock repository for testing."""
    repo = MagicMock(spec=Repository)
    repo.name = "test-repo"
    repo.owner = "test-owner"
    repo.artifact_snippets = set()
    repo.wf_artifact_np_findings = []
    return repo


def test_np_handler_init(mock_repo):
    """Test that NPHandler initializes correctly."""
    handler = NPHandler(
        repository=mock_repo,
        url="https://example.com",
        workflow_id="12345",
        include_all_artifact_secrets=False
    )
    
    assert handler.repository == mock_repo
    assert handler.url == "https://example.com"
    assert handler.workflow_id == "12345"
    assert handler.include_all_artifact_secrets is False


@patch('subprocess.run')
def test_np_scan_and_report_success(mock_subprocess_run, mock_repo):
    """Test successful execution of np_scan_and_report."""
    # Setup mocks
    mock_scan_result = MagicMock()
    mock_scan_result.returncode = 0
    
    mock_report_result = MagicMock()
    mock_report_result.returncode = 0
    
    # Set up subprocess.run to return our mock results
    mock_subprocess_run.side_effect = [mock_scan_result, mock_report_result]
    
    # Create temporary directories for testing
    with tempfile.TemporaryDirectory() as np_data_dir, \
         tempfile.TemporaryDirectory() as np_output_dir, \
         tempfile.TemporaryDirectory() as extracted_dir:
        
        # Initialize handler and patch _process_noseyparker_findings
        handler = NPHandler(mock_repo, "https://example.com", "12345", False)
        
        with patch.object(handler, '_process_noseyparker_findings') as mock_process:
            # Call the method
            handler.np_scan_and_report(
                np_data_dir, 
                np_output_dir, 
                "test-owner_test-repo", 
                extracted_dir
            )
            
            # Verify subprocess.run was called twice (scan and report)
            assert mock_subprocess_run.call_count == 2
            
            # Verify _process_noseyparker_findings was called with the right path
            expected_report_path = os.path.join(np_output_dir, "test-owner_test-repo_np.json")
            mock_process.assert_called_once_with(expected_report_path)


@patch('builtins.open', new_callable=mock_open, read_data=SAMPLE_NP_JSON)
@patch('gato.cli.output.Output.tabbed')
@patch('gato.cli.output.Output.error')
@patch('os.remove')
def test_process_noseyparker_findings(mock_remove, mock_error, mock_tabbed, mock_file, mock_repo):
    """Test processing of Nosey Parker findings."""
    # Create handler
    handler = NPHandler(mock_repo, "https://example.com", "12345", False)
    
    # Call the method with our test file path
    handler._process_noseyparker_findings("/path/to/report.json")
    
    # Verify the file was opened
    mock_file.assert_called_once_with("/path/to/report.json")
    
    # Verify Output.tabbed was called for each finding snippet
    assert mock_tabbed.call_count >= 2
    
    # Verify that findings were added to the repository
    # Note: Only 1 finding is expected because the AWS key contains "EXAMPLE" which is excluded
    assert len(mock_repo.wf_artifact_np_findings) == 1
    
    # Verify the file was removed at the end
    mock_remove.assert_called_once_with("/path/to/report.json") 