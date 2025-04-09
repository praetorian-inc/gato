import datetime

from typing import List

from gato.models.npfinding import NpFinding
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
        self.secrets: List[Secret] = []
        self.org_secrets: List[Secret] = []
        self.sh_workflow_names = []
        self.enum_time = datetime.datetime.now()
        self.default_branch = ""
        self.default_branch_protection = None

        self.permission_data = self.repo_data['permissions']
        self.sh_runner_access = False
        self.accessible_runners: List[Runner] = []
        self.runners: List[Runner] = []
        self.wf_artifact_np_findings: list[NpFinding] = []
        self.artifact_snippets = set()

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

    def update_time(self):
        """Update timestamp.
        """
        self.enum_time = datetime.datetime.now()

    def set_accessible_org_secrets(self, secrets: List[Secret]):
        """Sets organization secrets that can be read using a workflow in
        this repository.

        Args:
            secrets (List[Secret]): List of Secret wrapper objects.
        """
        self.org_secrets = secrets

    def set_default_branch_protection(self, branch: str, protection: str):
        self.default_branch = branch
        self.default_branch_protection = protection

    def set_secrets(self, secrets: List[Secret]):
        """Sets secrets that are attached to this repository.

        Args:
            secrets (List[Secret]): List of repo level secret wrapper objects.
        """
        self.secrets = secrets

    def set_runners(self, runners: List[Runner]):
        """Sets list of self-hosted runners attached at the repository level.
        """
        self.sh_runner_access = True
        self.runners = runners

    def add_self_hosted_workflows(self, workflows: list):
        """Add a list of workflow file names that run on self-hosted runners.
        """
        self.sh_workflow_names.extend(workflows)

    def add_accessible_runner(self, runner: Runner):
        """Add a runner is accessible by this repo. This runner could be org
        level or repo level.

        Args:
            runner (Runner): Runner wrapper object
        """
        self.sh_runner_access = True
        self.accessible_runners.append(runner)

    def toJSON(self):
        """Converts the repository to a Gato JSON representation.
        """
        representation = {
            "name": self.name,
            "private": self.is_private(),
            "default_branch": self.default_branch,
            "default_branch_protection": self.default_branch_protection,
            "enum_time": self.enum_time.ctime(),
            "permissions": self.permission_data,
            "can_fork": self.can_fork(),
            "runner_workflows": [wf for wf in self.sh_workflow_names],
            "accessible_runners": [runner.toJSON() for runner
                                   in self.accessible_runners],
            "repo_runners": [runner.toJSON() for runner in self.runners],
            "repo_secrets": [secret.toJSON() for secret in self.secrets],
            "org_secrets": [secret.toJSON() for secret in self.org_secrets],
            "wf_artifact_np_findings": [npfinding.toJSON() for npfinding in self.wf_artifact_np_findings],

        }

        return representation
