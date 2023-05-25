from typing import List

from gato.models.runner import Runner
from gato.models.secret import Secret


class Repository():
    """Simple wrapper class to provide accessor methods against the repository
    JSON response from GitHub.
    """

    def __init__(self, repo_data: dict):
        """Initialize wrapper class.

        Args:
            repo_json (dict): Dictionary from parsing JSON object returned from
            GitHub
        """
        self.repo_data = repo_data
        self.name = self.repo_data['full_name']
        self.org_name = self.name.split('/')[0]
        self.secrets = []
        self.org_secrets = []
        self.sh_workflow_names = []

        self.permission_data = self.repo_data['permissions']
        self.sh_runner_access = False
        self.accessible_runners = []
        self.runners = []

    def is_admin(self):
        return self.permission_data.get('admin', False)

    def is_maintainer(self):
        return self.permission_data.get('maintain', False)

    def can_push(self):
        return self.permission_data.get('push', False)

    def can_pull(self):
        return self.permission_data.get('pull', False)

    def is_private(self):
        return self.repo_data['private']

    def is_internal(self):
        return self.repo_data['visibility'] == 'internal'

    def is_public(self):
        return self.repo_data['visibility'] == 'public'

    def can_fork(self):
        return self.repo_data.get('allow_forking', False)

    def set_accessible_org_secrets(self, secrets: List[Secret]):
        """Sets organization secrets that can be read using a workflow in
        this repository.

        Args:
            secrets (list): _description_
        """
        self.org_secrets = secrets

    def set_secrets(self, secrets: List[Secret]):
        """Set repo-level secrets.

        Args:
            secrets (list): _description_
        """
        self.secrets = secrets

    def set_runners(self, runners: List[Runner]):
        """
        """
        self.sh_runner_access = True
        self.runners = runners

    def add_self_hosted_workflows(self, workflows: list):
        """
        """
        self.sh_workflow_names.extend(workflows)

    def add_accessible_runner(self, runner: Runner):
        """Add a runner is accessible by this repo. This runner could be org
        level or repo level.

        Args:
            runner (Runner): _description_
        """
        self.sh_runner_access = True
        self.accessible_runners.append(runner)

    def toJSON(self):
        """_summary_
        """
        representation = {
            "name": self.name,
            "permissions": self.permission_data,
            "accessible_runners": [runner.toJSON() for runner in self.accessible_runners],
            "runners": [runner.toJSON() for runner in self.runners],
            "repo_runners": [runner.toJSON() for runner in self.runners],
            "repo_secrets": [secret.toJSON() for secret in self.secrets],
            "org_secrets": [secret.toJSON() for secret in self.org_secrets],
        }

        return representation
