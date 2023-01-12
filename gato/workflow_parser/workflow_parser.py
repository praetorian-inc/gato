import logging
import yaml
from pathlib import Path
import os

logger = logging.getLogger(__name__)


class WorkflowParser():
    """Parser for YML files.

    This class is structurd to take a yaml file as input, it will then
    expose methods that aim to answer questions about the yaml file.

    This will allow for growing what kind of analytics this tool can perform
    as the project grows in capability.
    """

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
            print(f'        {self.wf_name} saved to: ' + os.path.join(
                dirpath, f'{self.repo_name}/{self.wf_name}'))

            return True

    def self_hosted(self):
        """Analyze if any jobs within the workflow utilize self-hosted runners.

        Returns:
           list: List of jobs within the workflow that utilize self-hosted
           runners.
        """

        sh_jobs = []
        for jobname, job_details in self.parsed_yml['jobs'].items():
            if 'runs-on' in job_details:
                runs_on = job_details['runs-on']
                if 'self-hosted' in runs_on:
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
