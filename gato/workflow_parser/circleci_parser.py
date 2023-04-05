import logging
import yaml
from pathlib import Path
import os

logger = logging.getLogger(__name__)


class CircleCIParser():
    """Parser for CircleCI YML files.

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
        Path(os.path.join(dirpath, f'{self.repo_name}/circleci/')).mkdir(
            parents=True, exist_ok=True)

        with open(os.path.join(
                dirpath, f'{self.repo_name}/circleci/{self.wf_name}'), 'w') as wf_out:
            wf_out.write(self.raw_yaml)
            print(f'        {self.wf_name} saved to: ' + os.path.join(
                dirpath, f'{self.repo_name}/circleci/{self.wf_name}'))

            return True

    def list_secrets(self):
        """Analyze secrets used in the CircleCI workflow.

        Returns:
           list: List of Circle CI secret used.
        """
        raise NotImplementedError()
