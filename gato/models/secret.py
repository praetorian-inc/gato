class Secret():
    """Simple wrapper class to parse secret response JSON from GitHub.
    """

    def __init__(self, secret_data: dict, parent: str):
        """_summary_

        Args:
            secret_data (dict): _description_
            selected_repos 
        """
        self.secret_data = secret_data
        self.name = secret_data['name']
        self.parent = parent

        if 'repos' in secret_data:
            self.visibility = "selected"
            self.selected_repos = secret_data['repos']
        else:
            self.visibility = "private"

    def is_repo_level(self):
        """Returns true if the secret is a repository level secret.

        Returns:
            bool: True if this is a repository level secret.
        """
        return '/' in self.parent
