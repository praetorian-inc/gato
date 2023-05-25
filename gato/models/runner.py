
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
            labels=None):

        self.runner_name = runner_name
        self.machine_name = machine_name
        self.os = os
        self.status = status
        self.labels = labels
