import pytest
import os
import pathlib

from unittest.mock import patch, mock_open

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
TEST_MATRIX = """
name: 'Test WF'

on:
  pull_request:
  workflow_dispatch:

jobs:
  invalid:
    runs-on: ubuntu-latest
    steps:
    - name: Execution
      run : |
           echo "Hello World!"
  invalid2:
    runs-on: [ubuntu-latest, windows-latest]
    steps:
    - name: Execution
      run : |
           echo "Hello World!"
  test:
    strategy:
      matrix:
        version: [1, 2, 3]
        system: [self-hosted, ubuntu-latest]
    runs-on: ${{matrix.system}}
    steps:

    - name: Execution
      run: |
          echo "Hello World and version ${{matrix.version}}"
  test2:
    strategy:
      matrix:
        version: [1, 2, 3]
        include:
          - device: windows-latest
          - device: self-hosted
    runs-on: ${{matrix.device}}
    steps:
    - name: Execution
      run: |
          echo "Hello World and version ${{matrix.version}}"
  broken:
    runs-on: ${{matrix.}}
    steps:
    - name: Execution
      run: |
          echo "Hello World and version ${{matrix.version}}"
  broken2:
    strategy:
      matrix:
        incorrect: self-hosted
    runs-on: ${{matrix.test}}
    steps:
    - name: Execution
      run: |
          echo "Hello World and version ${{matrix.version}}"
  test3:
    runs-on: [test123, windows-latest]
    steps:
    - name: Execution
      run: |
          echo "Hello World and version ${{matrix.version}}"
  test4:
    runs-on: test123
    steps:
    - name: Execution
      run: |
          echo "Hello World and version ${{matrix.version}}"
"""


def test_parse_workflow():

    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')

    sh_list = parser.self_hosted()

    assert len(sh_list) > 0


def test_analyze_entrypoints():

    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')

    with pytest.raises(NotImplementedError):
        parser.analyze_entrypoints()


def test_pull_request_target_trigger():

    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')

    with pytest.raises(NotImplementedError):
        parser.pull_req_target_trigger()


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


def test_no_jobs():
    WF = '\n'.join(TEST_WF.split('\n')[:5])

    parser = WorkflowParser(WF, 'unit_test', 'main.yml')

    sh_list = parser.self_hosted()

    assert len(sh_list) == 0


def test_matrix():

    parser = WorkflowParser(TEST_MATRIX, 'unit_test', 'main.yml')

    sh_list = parser.self_hosted()

    assert len(sh_list) == 4
