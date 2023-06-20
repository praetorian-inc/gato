from typing import List

from gato.models.organization import Organization
from gato.models.organization import Repository


class Execution():
    """Simple wrapper class to provide accessor methods against a full Gato
    execution run.
    """

    def __init__(self):
        """Initialize wrapper class.
        """
        self.user_details = None
        self.organizations: List[Organization] = []
        self.repositories: List[Repository] = []

    def add_organizations(self, organizations: List[Organization]):
        """Add list of organization wrapper objects.

        Args:
            organizations (List[Organization]): List of org wrappers.
        """
        self.organizations = organizations

    def add_repositories(self, repositories: List[Repository]):
        """Add list of organization wrapper objects.

        Args:
            organizations (List[Organization]): List of org wrappers.
        """
        self.repositories = repositories

    def set_user_details(self, user_details):
        """_summary_

        Args:
            user_details (dict): Details about the user's permissions.
        """
        self.user_details = user_details

    def toJSON(self):
        """Converts the run to Gato JSON representation"""

        if self.user_details:
            representation = {
                "username": self.user_details['user'],
                "scopes": self.user_details['scopes'],
                "enumeration": {
                    "organizations": [organization.toJSON() for organization in
                                      self.organizations],
                    "repositories": [repository.toJSON() for
                                     repository in self.repositories]
                }
            }

            return representation
