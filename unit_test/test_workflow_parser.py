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


# OIDC Tests

def test_no_oidc_connection():
    """Test that a workflow without OIDC connections returns an empty list."""
    yml_content = """
    name: Basic Workflow
    on:
      push:
        branches: [ main ]
    
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: Build
            run: echo "Building..."
    """
    
    parser = WorkflowParser(yml_content, "test/repo", "workflow.yml")
    oidc_jobs = parser.has_oidc_connection()
    
    assert len(oidc_jobs) == 0, "Workflow without OIDC should return empty list"


def test_workflow_level_oidc_permissions():
    """Test detection of workflow-level OIDC permissions."""
    yml_content = """
    name: Workflow with OIDC Permissions
    on:
      push:
        branches: [ main ]
    
    permissions:
      id-token: write
      contents: read
    
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: Build
            run: echo "Building..."
    """
    
    parser = WorkflowParser(yml_content, "test/repo", "workflow.yml")
    oidc_jobs = parser.has_oidc_connection()
    
    assert len(oidc_jobs) == 1, "Should detect one OIDC connection"
    assert oidc_jobs[0]['job_name'] == "workflow", "Should identify as workflow-level permissions"
    assert oidc_jobs[0]['type'] == "Workflow-level OIDC permissions", "Should have correct type"
    assert 'id-token' in oidc_jobs[0]['permissions'], "Should contain id-token permission"
    assert oidc_jobs[0]['permissions']['id-token'] == "write", "id-token permission should be write"


def test_job_level_oidc_permissions():
    """Test detection of job-level OIDC permissions."""
    yml_content = """
    name: Job with OIDC Permissions
    on:
      push:
        branches: [ main ]
    
    jobs:
      deploy:
        runs-on: ubuntu-latest
        permissions:
          id-token: write
          contents: read
        steps:
          - uses: actions/checkout@v3
          - name: Deploy
            run: echo "Deploying..."
    """
    
    parser = WorkflowParser(yml_content, "test/repo", "workflow.yml")
    oidc_jobs = parser.has_oidc_connection()
    
    assert len(oidc_jobs) == 1, "Should detect one OIDC connection"
    assert oidc_jobs[0]['job_name'] == "deploy", "Should identify job name correctly"
    assert 'id-token' in oidc_jobs[0]['permissions'], "Should contain id-token permission"
    assert oidc_jobs[0]['permissions']['id-token'] == "write", "id-token permission should be write"


def test_aws_oidc_connection():
    """Test detection of AWS OIDC connection with role information."""
    yml_content = """
    name: AWS OIDC Workflow
    on:
      push:
        branches: [ main ]
    
    permissions:
      id-token: write
      contents: read
    
    jobs:
      deploy-to-aws:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: Configure AWS Credentials
            uses: aws-actions/configure-aws-credentials@v2
            with:
              role-to-assume: arn:aws:iam::123456789012:role/my-github-actions-role
              aws-region: us-east-1
          - name: Deploy
            run: aws s3 sync . s3://my-bucket/
    """
    
    parser = WorkflowParser(yml_content, "test/repo", "workflow.yml")
    oidc_jobs = parser.has_oidc_connection()
    
    # There should be a workflow-level permission and a job with AWS action
    assert len(oidc_jobs) == 2, "Should detect two OIDC connections"
    
    # One should be workflow level
    workflow_level = next((j for j in oidc_jobs if j['job_name'] == 'workflow'), None)
    assert workflow_level is not None, "Should detect workflow-level permissions"
    
    # One should be job level with AWS details
    aws_job = next((j for j in oidc_jobs if j['job_name'] == 'deploy-to-aws'), None)
    assert aws_job is not None, "Should detect job-level AWS action"
    
    # Check AWS role information
    assert aws_job['provider'] == "AWS", "Should detect AWS provider"
    assert aws_job['assumed_role'] == "arn:aws:iam::123456789012:role/my-github-actions-role", "Should extract AWS role ARN"
    
    # Check the action details
    aws_action = aws_job['actions'][0]
    assert aws_action['action'] == "aws-actions/configure-aws-credentials@v2", "Should identify correct AWS action"
    assert aws_action['assumed_role'] == "arn:aws:iam::123456789012:role/my-github-actions-role", "Should extract role from action"


def test_google_cloud_oidc_connection():
    """Test detection of Google Cloud OIDC connection with service account."""
    yml_content = """
    name: GCP OIDC Workflow
    on:
      push:
        branches: [ main ]
    
    permissions:
      id-token: write
      contents: read
    
    jobs:
      deploy-to-gcp:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: Authenticate to Google Cloud
            uses: google-github-actions/auth@v1
            with:
              workload_identity_provider: projects/123456/locations/global/workloadIdentityPools/my-pool/providers/my-provider
              service_account: my-service-account@my-project.iam.gserviceaccount.com
          - name: Deploy
            run: gcloud app deploy
    """
    
    parser = WorkflowParser(yml_content, "test/repo", "workflow.yml")
    oidc_jobs = parser.has_oidc_connection()
    
    # Filter for the GCP job
    gcp_job = next((j for j in oidc_jobs if j['job_name'] == 'deploy-to-gcp'), None)
    assert gcp_job is not None, "Should detect GCP job"
    
    # Check GCP details
    assert gcp_job['provider'] == "Google Cloud", "Should detect Google Cloud provider"
    assert gcp_job['assumed_role'] == "Service Account: my-service-account@my-project.iam.gserviceaccount.com", "Should extract GCP service account"
    
    # Check the action details
    gcp_action = gcp_job['actions'][0]
    assert gcp_action['action'] == "google-github-actions/auth@v1", "Should identify correct GCP action"
    assert gcp_action['assumed_role'] == "Service Account: my-service-account@my-project.iam.gserviceaccount.com", "Should extract service account from action"


def test_azure_oidc_connection():
    """Test detection of Azure OIDC connection with client ID."""
    yml_content = """
    name: Azure OIDC Workflow
    on:
      push:
        branches: [ main ]
    
    permissions:
      id-token: write
      contents: read
    
    jobs:
      deploy-to-azure:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: Azure Login
            uses: azure/login@v1
            with:
              client-id: 11111111-1111-1111-1111-111111111111
              tenant-id: 22222222-2222-2222-2222-222222222222
              subscription-id: 33333333-3333-3333-3333-333333333333
          - name: Deploy
            run: az webapp up
    """
    
    parser = WorkflowParser(yml_content, "test/repo", "workflow.yml")
    oidc_jobs = parser.has_oidc_connection()
    
    # Filter for the Azure job
    azure_job = next((j for j in oidc_jobs if j['job_name'] == 'deploy-to-azure'), None)
    assert azure_job is not None, "Should detect Azure job"
    
    # Check Azure details
    assert azure_job['provider'] == "Azure", "Should detect Azure provider"
    assert "Client ID: 11111111-1111-1111-1111-111111111111" in azure_job['assumed_role'], "Should extract Azure client ID"
    assert "Tenant: 22222222-2222-2222-2222-222222222222" in azure_job['assumed_role'], "Should extract Azure tenant ID"
    assert "Subscription: 33333333-3333-3333-3333-333333333333" in azure_job['assumed_role'], "Should extract Azure subscription ID"


def test_vault_oidc_connection():
    """Test detection of HashiCorp Vault OIDC connection with role."""
    yml_content = """
    name: Vault OIDC Workflow
    on:
      push:
        branches: [ main ]
    
    permissions:
      id-token: write
      contents: read
    
    jobs:
      use-vault:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: Vault Auth
            uses: hashicorp/vault-action@v2
            with:
              url: https://vault.example.com
              role: my-github-role
              method: jwt
          - name: Use Secrets
            run: echo "Using secrets..."
    """
    
    parser = WorkflowParser(yml_content, "test/repo", "workflow.yml")
    oidc_jobs = parser.has_oidc_connection()
    
    # Filter for the Vault job
    vault_job = next((j for j in oidc_jobs if j['job_name'] == 'use-vault'), None)
    assert vault_job is not None, "Should detect Vault job"
    
    # Check Vault details
    assert vault_job['provider'] == "HashiCorp Vault", "Should detect HashiCorp Vault provider"
    assert vault_job['assumed_role'] == "Vault Role: my-github-role", "Should extract Vault role"


def test_multiple_oidc_providers():
    """Test detection of multiple OIDC providers in one workflow."""
    yml_content = """
    name: Multi-Provider OIDC Workflow
    on:
      push:
        branches: [ main ]
    
    permissions:
      id-token: write
      contents: read
    
    jobs:
      deploy-everywhere:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: AWS Auth
            uses: aws-actions/configure-aws-credentials@v2
            with:
              role-to-assume: arn:aws:iam::123456789012:role/github-role
              aws-region: us-east-1
          - name: GCP Auth
            uses: google-github-actions/auth@v1
            with:
              service_account: sa@project.iam.gserviceaccount.com
          - name: Azure Auth
            uses: azure/login@v1
            with:
              client-id: 11111111-1111-1111-1111-111111111111
    """
    
    parser = WorkflowParser(yml_content, "test/repo", "workflow.yml")
    oidc_jobs = parser.has_oidc_connection()
    
    # There should be 2 OIDC connections (workflow-level and job with multiple providers)
    assert len(oidc_jobs) == 2, "Should detect two OIDC connections"
    
    # Find the job with the providers
    job = next((j for j in oidc_jobs if j['job_name'] == 'deploy-everywhere'), None)
    assert job is not None, "Should detect job with multiple providers"
    
    # The job should have 3 actions
    assert len(job['actions']) == 3, "Should detect all three provider actions"
    
    # Check if the provider matches what's detected first (Azure in this case)
    assert job['provider'] == "Azure", "Job provider should be the first one detected (Azure)"
    
    # Check if all three actions are present
    action_types = [a['provider'] for a in job['actions']]
    assert "AWS" in action_types, "Should have AWS action"
    assert "Google Cloud" in action_types, "Should have Google Cloud action"
    assert "Azure" in action_types, "Should have Azure action"


def test_env_var_role_detection():
    """Test detection of roles from environment variables."""
    yml_content = """
    name: Env Var Role Workflow
    on:
      push:
        branches: [ main ]
    
    permissions:
      id-token: write
      contents: read
    
    jobs:
      aws-deploy:
        runs-on: ubuntu-latest
        permissions:
          id-token: write
          contents: read
        steps:
          - uses: actions/checkout@v3
          - name: Deploy
            env:
              AWS_ROLE_ARN: arn:aws:iam::123456789012:role/env-var-role
            run: |
              aws configure set region us-east-1
              aws s3 sync . s3://my-bucket/
    """
    
    parser = WorkflowParser(yml_content, "test/repo", "workflow.yml")
    oidc_jobs = parser.has_oidc_connection()
    
    # There should be workflow-level and a job
    assert len(oidc_jobs) == 2, "Should detect two OIDC connections"
    
    # Find the job
    job = next((j for j in oidc_jobs if j['job_name'] == 'aws-deploy'), None)
    assert job is not None, "Should detect job with environment variable"
    
    # Check if the role was detected from environment variables
    assert job['assumed_role'] == "arn:aws:iam::123456789012:role/env-var-role", "Should detect role from environment variable"
    assert job['provider'] == "Likely AWS", "Should detect likely AWS provider"
