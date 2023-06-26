import tempfile
import os
import subprocess
import logging

logger = logging.getLogger(__name__)


class Git:
    """This class is utilized to perfome a clone of a git repository using a
    PAT (sparse or otherwise) in order to perform deeper analysis on the
    repository content.
    """

    def __init__(self, pat, repo_name: str, username="Gato",
                 email="gato@gato.infosec", proxies=None,
                 github_url="github.com"):
        """Initialize the git abstraction class. This class managed a
        checked-out git repository located in a temporary directory.

        The directory is cleaned up upon object destruction, or can be manually
        cleaned up using a delete command.

        Args:
            pat (str): GitHub personal access token with necessary scopes.
            repo_name (str): Name of repository to interact with.
            username (str, optional): Username for the git commit
            email (str, optional): Email for the git commit
            http_proxy (str, optional): Clone through an HTTP proxy.
            Defaults to None.
            socks_proxy (str, optional): Clone through a SOCKS proxy.
            Defaults to None.
        """
        self.cloned = False
        if not github_url:
            self.github_url = "github.com"
        else:
            self.github_url = github_url

        if self.github_url != "github.com" or proxies:
            os.environ["GIT_SSL_NO_VERIFY"] = 'True'

        if proxies:
            os.environ["ALL_PROXY"] = proxies["https"]

        self.clone_comamnd = (
            "git clone --depth 1 --filter=blob:none --sparse"
            f" https://{pat}@{self.github_url}/{repo_name}"
        )

        self.config_command1 = (
            f"git config user.name '{username}'"
        )

        self.config_command2 = (
            f"git config user.email '{email}'"
        )

        if len(repo_name.split('/')) != 2:
            raise ValueError("Repository name but be in Org/Repo format!")
        self.repo_name = repo_name

    def perform_clone(self):
        """Performs the actual git clone operation.

        Returns:
            bool: True if the git clone operation was successful, False
            otherwise.
        """

        self.temp_folder = tempfile.TemporaryDirectory()

        try:
            new_wd = self.repo_name.split("/")[1]

            p = subprocess.Popen(
                self.clone_comamnd.split(" "),
                cwd=self.temp_folder.name,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p.wait()

            if p.returncode != 0:
                logger.error("Git clone operation did not succeed!")
                raise Exception("Git clone operation did not suceeed!")

            p = subprocess.Popen(
                self.config_command1.split(" "),
                cwd=os.path.join(self.temp_folder.name, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p.wait()

            p = subprocess.Popen(
                self.config_command2.split(" "),
                cwd=os.path.join(self.temp_folder.name, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p.wait()

            p1 = subprocess.Popen(
                "git sparse-checkout set .github".split(" "),
                cwd=os.path.join(self.temp_folder.name, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p1.wait()

            if p1.returncode != 0:
                logger.error("Git checkout operation did not succeed!")
                raise Exception("Git checkout operation did not suceeed!")
            self.cloned = True

        except Exception as e:
            logging.error(f"Exception during git clone of {self.repo_name}!")
            logging.error(f"Exception details: {str(e)}")
            if self.temp_folder:
                self.temp_folder.cleanup()
            return False

        return self.cloned

    def extract_workflow_ymls(self, repo_path: str = None):
        """Extracts and returns all github workflow .yml files located within
        the cloned repository.

        Args:
            repo_path (str, optional): Path on disk to repository to extract
            workflow yml files from. Defaults to repository associated with
            this object. Parameter intended for future uses and unit testing.
        Returns:
            list: List of yml files read from repository.
        """
        new_wd = self.repo_name.split("/")[1]

        if not repo_path:
            repo_path = self.temp_folder.name

        ymls = []

        if os.path.isdir(
            os.path.join(repo_path, new_wd, ".github", "workflows")
        ):
            workflows = os.listdir(
                os.path.join(repo_path, new_wd, ".github", "workflows")
            )

            for wf in workflows:
                wf_p = os.path.join(
                            repo_path, new_wd, ".github", "workflows", wf
                        )
                if os.path.isfile(wf_p):
                    with open(
                        wf_p,
                        "r",
                    ) as wf_in:
                        wf_yml = wf_in.read()

                        ymls.append((wf, wf_yml))
        return ymls

    def rewrite_commit(self, repo_path=None):
        """Rewrites commit history for repo so that it auto-closes the pull
        request.

        Args:
            repo_path (str, optional): Optional path to repo, otherwise uses
            the repository associated with this class. Mostly for unit testing.
            Defaults to None.

        Returns:
            bool: True if the commit was successfully re-written.
        """

        git_rebase = "git rebase -i HEAD^"

        repo_path = repo_path if repo_path else self.temp_folder.name
        new_wd = self.repo_name.split("/")[1]

        try:

            p = subprocess.Popen(
                git_rebase.split(' '),
                cwd=os.path.join(repo_path, new_wd),
                env={
                    **os.environ,
                    **{"GIT_SEQUENCE_EDITOR": "sed -i.bak 's/pick/drop/g'"}
                },
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p.wait()

        except Exception as e:
            logging.error("Exception during rebase!")
            logging.error(f"Exception details: {str(e)}")
            if self.temp_folder:
                self.temp_folder.cleanup()
            return False

        return True

    def commit_file(self, file_content: bytes, file_path: str,
                    repo_path: str = None, message: str = "Test Commit"):
        """Commit a file containing the provided content at the provided
        path.

        Args:
            repo_path (str, optional): Optional path to repo, otherwise uses
            the repository associated with this class. Mostly for unit testing.
            Defaults to None.

        Returns:
            str: The SHA1 hash of the HEAD revision, None if there was a
            failure.
        """
        repo_path = repo_path if repo_path else self.temp_folder.name
        new_wd = self.repo_name.split("/")[1]
        write_path = os.path.join(repo_path, new_wd, file_path)
        add_command = f"git add {file_path}"
        commit_command = 'git commit -m'
        rev_parse = "git rev-parse HEAD"

        ret = None

        try:
            os.makedirs(os.path.dirname(write_path), exist_ok=True)
            with open(write_path, 'wb') as outfile:
                outfile.write(file_content)

            p = subprocess.Popen(
                add_command.split(' '),
                cwd=os.path.join(repo_path, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p.wait()

            if p.returncode != 0:
                logger.error("Git add operation did not succeed!")
                raise Exception("Git add operation did not succeed!")

            cmd = commit_command.split(' ')
            cmd.append(message)
            p1 = subprocess.Popen(
                cmd,
                cwd=os.path.join(repo_path, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p1.wait()

            if p1.returncode != 0:
                logger.error("Git commit operation did not succeed!")
                raise Exception("Git commit operation did not suceeed!")

            p2 = subprocess.Popen(
                rev_parse.split(' '),
                cwd=os.path.join(repo_path, new_wd),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )
            p2.wait()

            if p2.returncode != 0:
                logger.error("Git rev-parse operation did not succeed!")
                raise Exception("Git rev-parse operation did not succeed!")

            ret = p2.communicate()[0].decode().strip()
        except Exception as e:
            logging.error("Exception during git commit!")
            logging.error(f"Exception details: {str(e)}")
            if self.temp_folder:
                self.temp_folder.cleanup()

        return ret

    def push_repository(self, upstream_branch: str, force: bool = False,
                        repo_path:
                        str = None):
        """Push to the remote repository.

        Args:
            upstream_branch (str): Name of upstream branch to push as.
            force (bool, optional): Whether the push should be forced. Defaults
            to False.
            repo_path (str, optional): Optional path to repo, otherwise uses
            the repository associated with this class. Mostly for unit testing.
            Defaults to None.

        Returns:
            bool: True if the push operation was successful.

        """
        rev_parse = ("git rev-parse --abbrev-ref HEAD")
        repo_path = repo_path if repo_path else self.temp_folder.name

        new_wd = self.repo_name.split("/")[1]

        p = subprocess.Popen(
                rev_parse.split(' '),
                cwd=os.path.join(repo_path, new_wd),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )
        p.wait()

        # Need to decode and strip the newline off.
        branch_name = p.communicate()[0].decode().strip()

        push_command = (
            f"git push --set-upstream origin {branch_name}:{upstream_branch}"
        )
        if force:
            push_command += " -f"

        logger.info(f"Executing: {push_command}")
        p1 = subprocess.Popen(
                push_command.split(' '),
                cwd=os.path.join(repo_path, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        p1.wait()

        if p1.returncode != 0:
            logger.error("Git push operation did not succeed!")
            return False

        return True

    def delete_branch(self, target_branch: str, repo_path: str = None):
        """Deletes a branch on the remote repository.

        Args:
            target_branch (str): Name of the branch to delete.
            repo_path (str, optional): Optional path to repo, otherwise uses
            the repository associated with this class. Mostly for unit testing.
            Defaults to None.

        Returns:
            bool: True of the branch was successfully deleted, False otherwise.
        """
        delete_command = f"git push origin --delete {target_branch} -f"
        repo_path = repo_path if repo_path else self.temp_folder.name

        new_wd = self.repo_name.split("/")[1]

        p = subprocess.Popen(
                delete_command.split(' '),
                cwd=os.path.join(repo_path, new_wd),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )
        p.wait()

        if p.returncode != 0:
            logger.error(f"Git push to delete branch {target_branch} "
                         "did not succeed!")
            return False

        return True

    def __del__(self):
        """Destructor for the object, cleans up the temporary directory."""
        if self.cloned:
            self.temp_folder.cleanup()
