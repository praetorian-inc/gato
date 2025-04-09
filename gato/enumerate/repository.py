import logging
import os
import re
import shutil
import tempfile

from gato.cli import Output
from gato.models import Repository, Secret, Runner
from gato.github import Api
from gato.workflow_parser import WorkflowParser
from gato.artifact_secrets_scanner.artifact_files import RecursiveExtractor
from gato.artifact_secrets_scanner.noseyparker import NPHandler

logger = logging.getLogger(__name__)


class RepositoryEnum():
    """Repository specific enumeration functionality.
    """

    def __init__(self, api: Api, skip_log: bool, output_yaml,
                 skip_sh_runner_enum: False):
        """Initialize enumeration class with instantiated API wrapper and CLI
        parameters.

        Args:
            api (Api): GitHub API wraper object.
        """
        self.api = api
        self.workflow_cache = {}
        self.skip_log = skip_log
        self.output_yaml = output_yaml
        self.skip_sh_runner_enum = skip_sh_runner_enum

    def __perform_runlog_enumeration(self, repository: Repository):
        """Enumerate for the presence of a self-hosted runner based on
        downloading historical runlogs.

        Args:
            repository (Repository): Wrapped repository object.

        Returns:
            bool: True if a self-hosted runner was detected.
        """
        runner_detected = False
        wf_runs = self.api.retrieve_run_logs(
            repository.name, short_circuit=True
        )

        if wf_runs:
            for wf_run in wf_runs:
                runner = Runner(
                    wf_run['runner_name'],
                    wf_run['runner_type'],
                    wf_run['token_permissions'],
                    runner_group=wf_run['runner_group'],
                    machine_name=wf_run['machine_name'],
                    labels=wf_run['requested_labels'],
                    non_ephemeral=wf_run['non_ephemeral']
                )

                repository.add_accessible_runner(runner)
            runner_detected = True

        return runner_detected

    def __perform_yml_enumeration(self, repository: Repository):
        """Enumerates the repository using the API to extract yml files. This
        does not generate any git clone audit log events.

        Args:
            repository (Repository): Wrapped repository object.

        Returns:
            list: List of workflows that execute on sh runner, empty otherwise.
        """
        runner_wfs = []

        if repository.name in self.workflow_cache:
            ymls = self.workflow_cache[repository.name]
        else:
            ymls = self.api.retrieve_workflow_ymls(repository.name)

        for (wf, yml) in ymls:
            try:
                parsed_yml = WorkflowParser(yml, repository.name, wf)
                if not parsed_yml:
                    continue

                self_hosted_jobs = parsed_yml.self_hosted()
                if self_hosted_jobs:
                    runner_wfs.append(wf)

                    if self.output_yaml:
                        success = parsed_yml.output(self.output_yaml)
                        if not success:
                            logger.warning("Failed to write yml to disk!")

            # At this point we only know the extension, so handle and
            #  ignore malformed yml files.
            except Exception as parse_error:
                Output.error(f"{wf}: {str(parse_error)}")
                logger.warning("Attmpted to parse invalid yaml!")

        return runner_wfs

    def enumerate_branch_protections(self, repository: Repository):
        """
        Check if branch protection is enabled on the default branch.

        Args:
            repository: Repository object to check branch protections for
        """
        # Check if the repository has a default branch
        if not repository.repo_data or "default_branch" not in repository.repo_data:
            Output.warn(f"No default branch found for {repository.name}!")
            repository.default_branch = None
            return False

        default_branch = repository.repo_data["default_branch"]
        Output.info(f"Default branch for {repository.name} is {default_branch}.")

        # Instead of directly checking protection status, we can check if there are any
        # branch protection rules by looking at the branch itself
        branch_info = self.api.call_get(
            f"/repos/{repository.name}/branches/{default_branch}"
        ).json()

        # The "protected" field is available in the branch info and readable by users with read access
        branch_protection = "Enabled" if branch_info.get("protected", False) else "Disabled"
        Output.info(f"Branch protection is {branch_protection.lower()} on {default_branch}.")

        repository.set_default_branch_protection(default_branch, branch_protection)
        return True

    def enumerate_workflow_artifacts(self, repository: Repository,
                                     include_all_artifact_secrets: False):
        """
        Scan workflow artifacts for secrets using noseyparker.

        Downloads recent workflow artifacts, extracts them, and scans for secrets.
        Only processes unique artifact names and unexpired artifacts.

        Args:
            repository: Repository object to scan artifacts for
        """

        Output.info(f"Scanning {repository.name} for workflow artifacts...")
        sanitized_org_repo_name = repository.name.replace("/", "_")
        # Create temporary directories for processing
        tmp_dir = "./artifact_tmp"
        os.makedirs(tmp_dir, exist_ok=True)
        artifact_dir = tempfile.mkdtemp(dir=tmp_dir, prefix=f".{sanitized_org_repo_name}_artifacts")
        extracted_dir = tempfile.mkdtemp(dir=tmp_dir, prefix=f".{sanitized_org_repo_name}_extracted")
        np_data_file = f"{tmp_dir}/.{sanitized_org_repo_name}_np.dat"
        np_output_dir = f"{tmp_dir}/.artifact_np_output"
        os.makedirs(np_output_dir, exist_ok=True)

        try:
            # Modify these constraints as desired

            # Track unique artifact names we've processed
            processed_names = set()
            # Track unique artifact sizes we've processed if the sizes are above
            # large_download_size_in_bytes / 2
            processed_sizes = set()
            artifact_count = 0
            # Cap at 50 artifacts per repo, do this to prevent infinite looping
            # and reduce the time. Increase this as needed.
            max_artifacts = 50
            # The artifact secrets scanner will only download `max_large_downloads`
            # number of downloads grater than this file size
            large_download_size_in_bytes = 536870912
            max_large_downloads = 10
            # The maximum size of a file that will be downloaded
            max_size = 2684354560
            large_downloads = 0

            # Get artifacts page by page
            page = 1
            while artifact_count < max_artifacts:

                artifacts = self.api.call_get(
                    f"/repos/{repository.name}/actions/artifacts",
                    params={"per_page": 100, "page": page}
                )

                if artifacts.status_code != 200:
                    Output.error(f"Failed to get artifacts for {repository.name}")
                    break

                artifacts = artifacts.json()

                if not artifacts["artifacts"]:
                    break

                for artifact in artifacts["artifacts"]:
                    # Skip if we've hit our limit
                    if artifact_count >= max_artifacts or artifact["expired"]:
                        artifact_count = max_artifacts + 1  # breaks loop once we see the first expired artifact
                        break

                    # Skip if we have already processed name or if the arifact is greater than the max size
                    if artifact["name"] in processed_names or int(artifact["size_in_bytes"]) > max_size:
                        continue

                    # Skip if it's large and we've already processed an artifact for this repo of that exact size
                    if int(artifact["size_in_bytes"]) > large_download_size_in_bytes / 2 \
                            and artifact["size_in_bytes"] in processed_sizes:
                        continue

                    if artifact["size_in_bytes"] > large_download_size_in_bytes:
                        if large_downloads >= max_large_downloads:
                            if large_downloads == max_large_downloads:
                                Output.warn("Maximum number of large downloads "
                                            f"reached for {repository.name}. "
                                            "Increase max_large_downloads if desired.")
                            large_downloads += 1
                            continue
                        large_downloads += 1

                    artifact_count += 1

                    try:
                        # Download the artifact
                        archive_resp = self.api.call_get(
                            artifact["archive_download_url"].replace("https://api.github.com", "")
                        )

                        if archive_resp.status_code != 200:
                            Output.error("Error downloading artifact. Make sure PAT has actions scope.")
                            continue
                        processed_names.add(artifact["name"])
                        processed_sizes.add(artifact["size_in_bytes"])
                        # Save with workflow run ID prefix
                        artifact_name = re.sub(r'[^a-zA-Z0-9.-]', '_',
                                               f"{artifact['workflow_run']['id']}_{artifact['name']}.zip")
                        artifact_path = os.path.join(artifact_dir, f"{artifact_name}")

                        with open(artifact_path, 'wb') as f:
                            f.write(archive_resp.content)

                        # Update file extension based on content type
                        if archive_resp.headers.get('content-type') == 'application/gzip':
                            new_path = artifact_path[:-4] + '.gz'
                            os.rename(artifact_path, new_path)
                            artifact_path = new_path

                        # Extract recursively
                        extractor = RecursiveExtractor(
                        )

                        try:

                            success = extractor.extract(
                                artifact_path,
                                custom_extract_path=extracted_dir,
                                max_workers=4  # Use 4 threads for parallel processing
                            )
                            if success:
                                logger.debug("Recursive extraction completed successfully!")
                        finally:
                            # Cleanup and np scanning will happen even if extraction fails
                            url = artifact["url"]
                            workflow_id = artifact["workflow_run"]["id"]
                            nphandler = NPHandler(repository, url, workflow_id, include_all_artifact_secrets)
                            nphandler.np_scan_and_report(np_data_file, np_output_dir, sanitized_org_repo_name, extracted_dir)
                            extractor.cleanup()

                    except Exception as e:
                        logger.warning(f"Error processing artifact {artifact['name']}: {e}")
                        continue

                page += 1

        finally:
            # Cleanup again just in case
            shutil.rmtree(artifact_dir, ignore_errors=True)
            shutil.rmtree(extracted_dir, ignore_errors=True)
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def enumerate_repository(self, repository: Repository, large_org_enum=False):
        """Enumerate a repository, and check everything relevant to
        self-hosted runner abuse that that the user has permissions to check.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
            clone (bool, optional):  Whether to use repo contents API
            in order to analayze the yaml files. Defaults to True.
        """
        runner_detected = False

        repository.update_time()

        if not repository.can_pull() and not self.api.is_app_token():
            Output.error("The user cannot push or pull, skipping.")
            return

        if not self.skip_sh_runner_enum:
            if repository.is_admin():
                runners = self.api.get_repo_runners(repository.name)

                if runners:
                    repo_runners = [
                        Runner(
                            runner,
                            machine_name=None,
                            os=runner['os'],
                            status=runner['status'],
                            labels=runner['labels']
                        )
                        for runner in runners
                    ]

                    repository.set_runners(repo_runners)

            workflows = self.__perform_yml_enumeration(repository)

            if len(workflows) > 0:
                repository.add_self_hosted_workflows(workflows)
                runner_detected = True

            if not self.skip_log:
                # If we are enumerating an organization, only enumerate runlogs if
                # the workflow suggests a sh_runner.
                if large_org_enum and runner_detected:
                    self.__perform_runlog_enumeration(repository)

                # If we are doing internal enum, get the logs, because coverage is
                # more important here and it's ok if it takes time.
                elif not repository.is_public() or not large_org_enum:
                    runner_detected = self.__perform_runlog_enumeration(repository)

            if runner_detected:
                # Only display permissions (beyond having none) if runner is
                # detected.
                repository.sh_runner_access = True

    def enumerate_repository_secrets(
            self, repository: Repository):
        """Enumerate secrets accessible to a repository.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
        """
        if repository.can_push():
            secrets = self.api.get_secrets(repository.name)

            repo_secrets = [
                Secret(secret, repository.name) for secret in secrets
            ]

            repository.set_secrets(repo_secrets)

            org_secrets = self.api.get_repo_org_secrets(repository.name)
            org_secrets = [
                Secret(secret, repository.org_name)
                for secret in org_secrets
            ]

            if org_secrets:
                repository.set_accessible_org_secrets(org_secrets)

    def construct_workflow_cache(self, yml_results):
        """Creates a cache of workflow yml files retrieved from graphQL. Since
        graphql and REST do not have parity, we still need to use rest for most
        enumeration calls. This method saves off all yml files, so during org
        level enumeration if we perform yml enumeration the cached file is used
        instead of making github REST requests.

        Args:
            yml_results (list): List of results from individual GraphQL queries
            (100 nodes at a time).
        """
        for result in yml_results:
            # If we get any malformed/missing data just skip it and
            # Gato will fall back to the contents API for these few cases.
            if not result or \
                    'nameWithOwner' not in result or \
                    'object' not in result or \
                    not result['object']:
                continue

            owner = result['nameWithOwner']

            if owner not in self.workflow_cache:
                self.workflow_cache[owner] = list()

            for yml_node in result['object']['entries']:
                yml_name = yml_node['name']
                if yml_name.lower().endswith('yml') or yml_name.lower().endswith('yaml'):
                    contents = yml_node['object']['text']
                    self.workflow_cache[owner].append((yml_name, contents))
