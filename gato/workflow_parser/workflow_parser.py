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
