import json
import os
import shutil
import subprocess

from gato.cli.output import Output
from gato.models.npfinding import NpFinding
from gato.models.repository import Repository


class NPHandler:
    """Internal handler for Nosey Parker processing."""

    def __init__(self, repository: Repository, url, workflow_id, include_all_artifact_secrets: False):
        self.repository = repository
        self.url = url
        self.workflow_id = workflow_id
        self.include_all_artifact_secrets = include_all_artifact_secrets

    def np_scan_and_report(self, np_data_file, np_output_dir, sanitized_org_repo_name, extracted_dir):
        shell = os.environ.get('SHELL', '/bin/sh')

        scan_cmd = f"noseyparker scan -d {np_data_file} {extracted_dir}"
        scan_result = subprocess.run(
            [shell, '-l', '-c', scan_cmd],
            capture_output=True,
            text=True
        )

        if scan_result.returncode != 0:
            Output.error(f"Noseyparker scan failed: {scan_result.stderr}")
            return

        # Generate report
        report_path = os.path.join(np_output_dir, f"{sanitized_org_repo_name}_np.json")
        report_cmd = f"noseyparker report -d  {np_data_file} -f json -o {report_path}"
        report_result = subprocess.run(
            [shell, '-l', '-c', report_cmd],
            capture_output=True,
            text=True
        )

        shutil.rmtree(f"{np_data_file}", ignore_errors=False)

        if report_result.returncode != 0:
            Output.error(f"Noseyparker report failed: {report_result.stderr}")
            return

        # Parse and display findings
        self._process_noseyparker_findings(report_path)

    def _process_noseyparker_findings(self, report_path: str):
        """
        Process and display noseyparker findings.

        Args:
            report_path: Path to noseyparker JSON report
            repository: Repository being scanned
        """
        try:
            with open(report_path) as f:
                findings = json.load(f)

            if findings:
                for finding in findings:
                    if not self.include_all_artifact_secrets:
                        # added filters to remove common false positives
                        # can remove to get more information if desired
                        if finding['rule_name'] == "PEM-Encoded Private Key" or \
                           finding['rule_name'] == "Base64-PEM-Encoded Private" or \
                           finding['rule_name'] == "Generic Password":
                            continue

                    np_finding = NpFinding(
                        rule=finding['rule_name'],
                        matches=[],
                        url=self.url,
                        workflow_id=self.workflow_id,
                    )
                    add_finding = True

                    for match in finding['matches']:
                        newmatch = {}
                        if 'snippet' in match:
                            snippet = match['snippet']['matching']

                            # only output one finding for identical matches across the entire repository.
                            # If we find secrets that could be repeated elsewhere in the repo,
                            # consider re-running on the repo with this disabled.
                            if snippet in self.repository.artifact_snippets and np_finding.matches == []:
                                add_finding = False
                                continue

                            # Excluding common false positives
                            if not self.include_all_artifact_secrets:
                                exclusions = ["test", "TEST", "EXAMPLE",
                                              "example", "anon", "passwd",
                                              "pwd", "secretsmanager",
                                              "secret_config"]

                                if any(exclusion in snippet for exclusion in exclusions):
                                    add_finding = False
                                    continue

                                # Excluding api keys in js files as these are commonly false positives
                                path = match.get('provenance', [{}])[0].get('path', 'Unknown')
                                if (finding['rule_name'] == "Generic API Key"
                                        and ".js" in path) \
                                        or "README.md" in path:
                                    add_finding = False
                                    continue

                            Output.tabbed(f"Match: {snippet}")
                            newmatch["snippet"] = snippet

                            self.repository.artifact_snippets.add(snippet)

                        if 'provenance' in match:
                            Output.tabbed(f"Path: {match.get('provenance', [{}])[0].get('path', 'Unknown')}")
                            newmatch["provenance"] = match.get('provenance', [{}])[0].get('path', 'Unknown')

                        Output.tabbed("---")
                        np_finding.matches.append(newmatch)

                    if add_finding:
                        self.repository.wf_artifact_np_findings.append(np_finding)

            os.remove(report_path)
        except Exception as e:
            Output.error(f"Failed to process findings: {e}")
