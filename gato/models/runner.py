
class Runner:
    """Wrapper object for a self-hosted runner. Can represent a runner obtained
    via workflow log parsing or administrative query of repo/org level
    self-hosted runners.
    """

    def __init__(
            self,
            runner_name,
            machine_name=None,
            os=None,
            status=None,
            labels=[]):

        self.runner_name = runner_name
        self.machine_name = machine_name
        self.os = os
        self.status = status
        self.labels = labels

    def toJSON(self):
        """Converts the repository to a Gato JSON representation.
        """
        representation = {
            "name": self.runner_name,
            "machine_name": self.machine_name if self.machine_name else "Unknown",
            "os": self.os if self.os else "Unknown",
            "status": self.status if self.status else "Unknown",
            "labels": [label for label in self.labels]
        }

        return representation
