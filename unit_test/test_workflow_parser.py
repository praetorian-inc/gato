import pytest
import os
import pathlib

from unittest.mock import patch, ANY, mock_open

from gato.workflow_parser import WorkflowParser

TEST_WF = """
name: 'Test WF'

on:
  pull_request:
  workflow_dispatch:

jobs:
  test:
    runs-on: ['self-hosted']
    steps:

    - name: Execution
      run: |
          echo "Hello World and bad stuff!"
"""


def test_parse_workflow():

    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')

    sh_list = parser.self_hosted()

    assert len(sh_list) > 0


def test_workflow_write():

    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')

    curr_path = pathlib.Path(__file__).parent.resolve()
    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/")

    with patch("builtins.open", mock_open(read_data="")) as mock_file:
        parser.output(test_repo_path)

        mock_file().write.assert_called_once_with(
            parser.raw_yaml
        )
