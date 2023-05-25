from typing import List

from gato.models import Runner, Secret, Repository

class Organization():

    def __init__(self, org_data: dict, user_scopes):
        """_summary_

        Args:
            org_data (dict): _description_
        """
        self.name = None
        self.org_admin_user = False
        self.org_admin_scopes = False
        self.org_admin_user = False
        self.org_member = False
        self.secrets = []
        self.runners = []
        self.sso_enabled = False

        self.name = org_data['login']

        # If fields such as billing email are populated, then the user MUST
        # be an organization owner. If not, then the user is a member (for
        # private repos) or
        if "billing_email" in org_data and org_data["billing_email"] is not None:
            if "admin:org" in user_scopes:
                self.org_admin_scopes = True
                self.org_admin_user = True
            self.org_member = True
        elif "billing_email" in org_data:
            self.org_admin_user = False
            self.org_member = True
        else:
            self.org_admin_user = False
            self.org_member = False

    def set_secrets(self, secrets: list[Secret]):
        """Set repo-level secrets.

        Args:
            secrets (list): _description_
        """
        self.secrets = secrets

    def set_public_repos(self, repos: list[Repository]):
        """Set list of public repos
        """
        self.public_repos = repos

    def set_private_repos(self, repos: list[Repository]):
        """_summary_

        Args:
            repos (List[Repository]): _description_
        """
        self.private_repos = repos

    def set_runners(self, runners: list[Runner]):
        """_summary_

        Args:
            runners (List[Runner]): _description_
        """

        self.runners = runners
