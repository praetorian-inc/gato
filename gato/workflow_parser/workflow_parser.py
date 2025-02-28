import logging
import yaml
from pathlib import Path
import os
import re

logger = logging.getLogger(__name__)


class WorkflowParser():
    """Parser for YML files.

    This class is structurd to take a yaml file as input, it will then
    expose methods that aim to answer questions about the yaml file.

    This will allow for growing what kind of analytics this tool can perform
    as the project grows in capability.
    """

    GITHUB_HOSTED_LABELS = [
        'ubuntu-latest',
        'macos-latest',
        'macOS-latest',
        'windows-latest',
        'ubuntu-18.04',  # deprecated, but we don't want false positives on older repos.
        'ubuntu-20.04',
        'ubuntu-22.04',
        'windows-2022',
        'windows-2019',
        'windows-2016',  # deprecated, but we don't want false positives on older repos.
        'macOS-14',
        'macOS-13',
        'macOS-12',
        'macOS-11',
        'macos-11',
        'macos-12',
        'macos-13',
        'macos-13-xl',
        'macos-14',
    ]

    LARGER_RUNNER_REGEX_LIST = r'(windows|ubuntu)-(22.04|20.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb'
    MATRIX_KEY_EXTRACTION_REGEX = r'{{\s*matrix\.([\w-]+)\s*}}'

    def __init__(self, workflow_yml: str, repo_name: str, workflow_name: str):
        """Initialize class with workflow file.

        Args:
            workflow_yml (str): String containing yaml file read in from
            repository.
            repo_name (str): Name of the repository.
            workflow_name (str): name of the workflow file
        """
        self.parsed_yml = yaml.safe_load(workflow_yml)
        self.raw_yaml = workflow_yml
        self.repo_name = repo_name
        self.wf_name = workflow_name

    def output(self, dirpath: str):
        """Write this yaml file out to the provided directory.

        Args:
            dirpath (str): Directory to save the yaml file to.

        Returns:
            bool: Whether the file was successfully written.
        """
        Path(os.path.join(dirpath, f'{self.repo_name}')).mkdir(
            parents=True, exist_ok=True)

        with open(os.path.join(
                dirpath, f'{self.repo_name}/{self.wf_name}'), 'w') as wf_out:
            wf_out.write(self.raw_yaml)
            return True

    def self_hosted(self):
        """Analyze if any jobs within the workflow utilize self-hosted runners.

        Returns:
           list: List of jobs within the workflow that utilize self-hosted
           runners.
        """
        sh_jobs = []
        if not self.parsed_yml or 'jobs' not in self.parsed_yml:
            return sh_jobs

        for jobname, job_details in self.parsed_yml['jobs'].items():
            if 'runs-on' in job_details:
                runs_on = job_details['runs-on']
                # Clear cut
                if 'self-hosted' in runs_on:
                    sh_jobs.append((jobname, job_details))
                elif 'matrix.' in runs_on:
                    # We need to check each OS in the matrix strategy.
                    # Extract the matrix key from the variable
                    matrix_match = re.search(self.MATRIX_KEY_EXTRACTION_REGEX, runs_on)

                    if matrix_match:
                        matrix_key = matrix_match.group(1)
                    else:
                        continue
                    # Check if strategy exists in the yaml file
                    if 'strategy' in job_details and 'matrix' in job_details['strategy']:
                        matrix = job_details['strategy']['matrix']

                        # Use previously acquired key to retrieve list of OSes
                        if matrix_key in matrix:
                            os_list = matrix[matrix_key]
                        elif 'include' in matrix:
                            inclusions = matrix['include']
                            os_list = []
                            for inclusion in inclusions:
                                if matrix_key in inclusion:
                                    os_list.append(inclusion[matrix_key])
                        else:
                            continue

                        # We only need ONE to be self hosted, others can be
                        # GitHub hosted
                        for key in os_list:
                            if type(key) is str:
                                if key not in self.GITHUB_HOSTED_LABELS and not re.match(self.LARGER_RUNNER_REGEX_LIST, key):
                                    sh_jobs.append((jobname, job_details))
                                    break
                    pass
                else:
                    if type(runs_on) is list:
                        for label in runs_on:
                            if label not in self.GITHUB_HOSTED_LABELS and \
                                    not re.match(self.LARGER_RUNNER_REGEX_LIST, label):
                                sh_jobs.append((jobname, job_details))
                                break
                    elif type(runs_on) is str:
                        if runs_on in self.GITHUB_HOSTED_LABELS or \
                                re.match(self.LARGER_RUNNER_REGEX_LIST, runs_on):
                            continue
                        sh_jobs.append((jobname, job_details))
        return sh_jobs

    def analyze_entrypoints(self):
        """Returns a list of tasks within the self hosted workflow include the
        `run` step.
        """

        sh_jobs = self.self_hosted()

        if sh_jobs:
            steps = sh_jobs[0][1]['steps']

            for step in steps:
                if 'run' in step:
                    step_name = step['name']
                    logging.debug(f"Analyzing job step: {step_name}")
                    logging.debug(f"Step content: {step['run']}")

        raise NotImplementedError()

    def pull_req_target_trigger(self):
        """Analyze if the workflow is set to execute on the
        `pull-request-target` trigger, and if the workflow
        checks out the remote head in a subsequent call.
        """
        raise NotImplementedError()

    def has_oidc_connection(self):
        """Analyze if any jobs within the workflow use OIDC connections
        to authenticate with cloud providers or external services.

        Returns:
            list: List of dictionaries containing OIDC connection details
        """
        oidc_jobs = []
        
        if not self.parsed_yml or 'jobs' not in self.parsed_yml:
            return oidc_jobs
        
        # OIDC provider mappings
        oidc_provider_actions = {
            'aws-actions/configure-aws-credentials': 'AWS',
            'google-github-actions/auth': 'Google Cloud',
            'azure/login': 'Azure',
            'hashicorp/vault-action': 'HashiCorp Vault',
            'auth0/action-credentials': 'Auth0',
            'actions/create-github-app-token': 'GitHub App',
            'actions/create-github-token': 'GitHub',
            'azure/aks-set-context': 'Azure AKS',
            'aws-actions/amazon-ecr-login': 'AWS ECR',
            'gcp-auth': 'Google Cloud'
        }
        
        # Check workflow-level permissions first
        workflow_level_oidc = False
        if 'permissions' in self.parsed_yml:
            permissions = self.parsed_yml['permissions']
            if isinstance(permissions, dict) and permissions.get('id-token') == 'write':
                # Workflow has OIDC permissions at top level
                workflow_level_oidc = True
                oidc_jobs.append({
                    'job_name': 'workflow',
                    'type': 'Workflow-level OIDC permissions',
                    'provider': 'Unknown (permissions set at workflow level)',
                    'permissions': permissions,
                    'assumed_role': None
                })
        
        # Check each job
        for jobname, job_details in self.parsed_yml['jobs'].items():
            job_has_oidc = False
            oidc_details = {
                'job_name': jobname,
                'type': 'Job-level OIDC permissions',
                'provider': 'Unknown',
                'permissions': None,
                'actions': [],
                'assumed_role': None
            }
            
            # Check job-specific permissions
            if 'permissions' in job_details:
                permissions = job_details['permissions']
                if isinstance(permissions, dict) and permissions.get('id-token') == 'write':
                    job_has_oidc = True
                    oidc_details['permissions'] = permissions
            
            # Check for OIDC provider actions
            if 'steps' in job_details:
                for step in job_details['steps']:
                    if 'uses' in step:
                        action = step['uses'].split('@')[0].lower()
                        for pattern, provider in oidc_provider_actions.items():
                            if pattern.lower() in action:
                                job_has_oidc = True
                                oidc_details['provider'] = provider
                                
                                action_info = {
                                    'action': step['uses'],
                                    'provider': provider,
                                    'step_name': step.get('name', 'Unnamed step'),
                                    'assumed_role': None
                                }
                                
                                # Extract role information based on provider
                                if 'with' in step:
                                    with_params = step['with']
                                    
                                    # AWS role extraction
                                    if provider == 'AWS':
                                        role = with_params.get('role-to-assume') or with_params.get('aws-role-to-assume')
                                        if role:
                                            action_info['assumed_role'] = role
                                            if not oidc_details['assumed_role']:
                                                oidc_details['assumed_role'] = role
                                    
                                    # Google Cloud role extraction
                                    elif provider == 'Google Cloud':
                                        service_account = with_params.get('service_account') or with_params.get('credentials_json')
                                        workload_identity_provider = with_params.get('workload_identity_provider')
                                        
                                        if service_account:
                                            action_info['assumed_role'] = f"Service Account: {service_account}"
                                            if not oidc_details['assumed_role']:
                                                oidc_details['assumed_role'] = f"Service Account: {service_account}"
                                        elif workload_identity_provider:
                                            action_info['assumed_role'] = f"Workload Identity: {workload_identity_provider}"
                                            if not oidc_details['assumed_role']:
                                                oidc_details['assumed_role'] = f"Workload Identity: {workload_identity_provider}"
                                    
                                    # Azure role extraction
                                    elif provider == 'Azure':
                                        client_id = with_params.get('client-id')
                                        tenant_id = with_params.get('tenant-id')
                                        subscription_id = with_params.get('subscription-id')
                                        
                                        if client_id:
                                            role_info = f"Client ID: {client_id}"
                                            if tenant_id:
                                                role_info += f", Tenant: {tenant_id}"
                                            if subscription_id:
                                                role_info += f", Subscription: {subscription_id}"
                                                
                                            action_info['assumed_role'] = role_info
                                            if not oidc_details['assumed_role']:
                                                oidc_details['assumed_role'] = role_info
                                    
                                    # HashiCorp Vault role extraction
                                    elif provider == 'HashiCorp Vault':
                                        role = with_params.get('role') or with_params.get('vault-role')
                                        if role:
                                            action_info['assumed_role'] = f"Vault Role: {role}"
                                            if not oidc_details['assumed_role']:
                                                oidc_details['assumed_role'] = f"Vault Role: {role}"
                                
                                oidc_details['actions'].append(action_info)
            
            # If no specific provider was found but the job has OIDC permissions
            if job_has_oidc and not oidc_details['actions'] and oidc_details['provider'] == 'Unknown':
                # Try to infer provider from other job details
                if any('aws' in str(step).lower() for step in job_details.get('steps', [])):
                    oidc_details['provider'] = 'Likely AWS'
                elif any('gcp' in str(step).lower() or 'google' in str(step).lower() for step in job_details.get('steps', [])):
                    oidc_details['provider'] = 'Likely Google Cloud'
                elif any('azure' in str(step).lower() for step in job_details.get('steps', [])):
                    oidc_details['provider'] = 'Likely Azure'
                
                # Look for environment variables that might indicate role assumption
                for step in job_details.get('steps', []):
                    if 'env' in step:
                        env_vars = step['env']
                        # AWS role in environment variables
                        aws_role = env_vars.get('AWS_ROLE_ARN') or env_vars.get('AWS_ROLE_TO_ASSUME')
                        if aws_role and not oidc_details['assumed_role']:
                            oidc_details['assumed_role'] = aws_role
                            break
            
            if job_has_oidc:
                oidc_jobs.append(oidc_details)
        
        return oidc_jobs
