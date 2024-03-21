class Variable():
    """Simple wrapper class to parse variable response JSON from GitHub. Used
        primarily to facilitate JSON generation and to support future
        in-depth analysis of run logs and/or workflows.
    """

    def __init__(self, variable_data: dict, parent: str):
        """Initialize wrapper object for secret.

        Args:
            variable_data (dict): Data about secret returned from the GitHub API.
            parent (str): Repository or organization name that this secret
            belongs to.
        """
        self.variable_data = variable_data
        self.name = variable_data['name']
        self.value = variable_data['value']
        self.parent = parent

        if 'repos' in variable_data:
            self.visibility = "selected"
            self.selected_repos = variable_data['repos']
        else:
            self.visibility = "private"

    def is_repo_level(self):
        """Returns true if the secret is a repository level secret.

        Returns:
            bool: True if this is a repository level secret.
        """
        return '/' in self.parent

    def toJSON(self):
        """Converts the repository to a Gato JSON representation.
        """
        representation = {
            "name": self.name,
            "value": self.value,
            "updated_at": self.variable_data['updated_at'],
            "created_at": self.variable_data['created_at'],
            "visibiliy": self.visibility,
            "repo_level": self.is_repo_level()
        }

        return representation
