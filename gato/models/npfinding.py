class NpFinding:
    """Simple wrapper class to parse third party pipeline JSON from GitHub.
    """

    def __init__(self, rule, matches, url, workflow_id):
        """Initialize wrapper object for third party pipeline.

        """
        self.rule = rule
        self.matches = matches
        self.url = url
        self.workflow_id = workflow_id

    def toJSON(self):
        """Converts the NP finding to a Gato JSON representation."""
        representation = {
            "rule": self.rule,
            "URL": self.url,
            "Workflow_ID": self.workflow_id,
            "matches": [match for match in self.matches]
        }

        return representation
