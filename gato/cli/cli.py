import argparse
import os
import re

from packaging import version

from colorama import Fore, Style
from gato.cli import RED_DASH


from gato.enumerate import Enumerator
from gato.attack import Attacker
from gato.search import Searcher
from gato.models import Execution

from gato import util
from gato.util.arg_utils import StringType
from gato.util.arg_utils import WriteableDir
from gato.util.arg_utils import ReadableFile
from gato.util.arg_utils import is_command_available
import gato.git as git
from gato.cli import Output


REQUIRED_GIT_VERSION = "2.27"


def cli(args):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            f'{Fore.YELLOW}This tool requires a GitHub PAT to'
            f' function!{Style.RESET_ALL}\n\nThis can be passed via the'
            ' "GH_TOKEN" environment variable, or if it is not set,\nthen the'
            ' application will prompt you for one.'
        ),
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    configure_parser_general(parser)

    parser.add_argument(
        "--api-url", "-u",
        help=(
            f"{Fore.RED}{Output.bright('!! Experimental !!')}\n"
            "Github API URL to target. \n"
            "Defaults to 'https://api.github.com'"
        ),
        metavar="https://api.github-url.com/api/v3",
        required=False,
    )

    attack_parser = subparsers.add_parser(
        "attack", help="CI/CD Attack Capabilities", aliases=["a"],
        formatter_class=argparse.RawTextHelpFormatter
    )
    attack_parser.set_defaults(func=attack)

    enumerate_parser = subparsers.add_parser(
        "enumerate", help="Enumeration Capabilities", aliases=["enum", "e"],
        formatter_class=argparse.RawTextHelpFormatter
    )
    enumerate_parser.set_defaults(func=enumerate)

    search_parser = subparsers.add_parser(
        "search", help="Search Capabilities Using GitHub's API", aliases=["s"],
        formatter_class=argparse.RawTextHelpFormatter
    )
    search_parser.set_defaults(func=search)

    configure_parser_attack(attack_parser)
    configure_parser_enumerate(enumerate_parser)
    configure_parser_search(search_parser)

    arguments = parser.parse_args(args)

    Output(arguments.supress, not arguments.no_color)

    validate_arguments(arguments, parser)
    validate_git_config(parser)

    validate_noseyparker(arguments, parser)

    Output.splash()

    arguments.func(arguments, subparsers)


def validate_noseyparker(arguments, parser):
    args_dict = vars(arguments)

    if "enum_wf_artifacts" in args_dict and args_dict["enum_wf_artifacts"] \
            and not is_command_available("noseyparker"):
        parser.error(
            f"{Fore.RED} [-] The 'noseyparker' application is either not installed, "
            "or not present on the path! To install, download a release from "
            "https://github.com/praetorian-inc/noseyparker/releases and place it in your $PATH."
        )


def validate_arguments(args, parser):
    if "GH_TOKEN" not in os.environ:
        gh_token = input(
            "No 'GH_TOKEN' environment variable set! Please enter a GitHub"
            " PAT.\n"
        )
    else:
        gh_token = os.environ["GH_TOKEN"]

    if "github_pat_" in gh_token:
        parser.error(
            f"{Fore.RED}[!] Fine-grained PATs are currently not supported!"
        )

    if not ("ghp_" in gh_token or "gho_" in gh_token or "ghu_" in
            gh_token or "ghs_" in gh_token or re.match('^[a-fA-F0-9]{40}$', gh_token)):
        parser.error(f"{Fore.RED}[!]{Style.RESET_ALL} Provided GitHub PAT is"
                     " malformed!")

    args_dict = vars(args)
    args_dict["gh_token"] = gh_token

    if args.socks_proxy and args.http_proxy:
        parser.error(
            f"{Fore.RED}[-]{Style.RESET_ALL} You cannot use a SOCKS and HTTP"
            " proxy at the same time!"
        )


def validate_git_config(parser):
    git_status = git.path_check()
    if not git_status:
        parser.error(
            f"{Fore.RED} [-] The 'git' application is either not installed, "
            "or not present on the path!"
        )

    git_version = git.version_check()

    if git_version:
        git_version = git_version.split('.')[0:3]  # Keep only the first three parts
        git_version = '.'.join(git_version)
        git_version = version.parse(git_version)
        if git_version < version.parse(REQUIRED_GIT_VERSION):
            parser.error(
                f"{Fore.RED} This tool requires a 'git' version of at least"
                f" {REQUIRED_GIT_VERSION}!"
            )
    else:
        parser.error(
            f"{Fore.RED} 'git --version' returned unexpected output!"
        )


def attack(args, parser):
    parser = parser.choices["attack"]
    if not (args.workflow or args.pull_request or args.secrets):
        parser.error(f"{Fore.RED}[!] You must select one of the attack modes, "
                     "workflow, pr, or secrets.")

    if args.custom_file and (args.command or
                             args.name):
        parser.error(f"{Fore.RED}[!] A shell command or workflow name"
                     f" cannot be used with a custom workflow.")

    if args.secrets and args.command:
        parser.error(
            f"{Fore.RED}[!] A command cannot be used with secrets exfil!."
        )

    if not args.custom_file:
        args.command = args.command if args.command else "whoami"
        args.name = args.name if args.name else "test"

    timeout = int(args.timeout)

    gh_attack_runner = Attacker(
        args.gh_token,
        author_email=args.author_email,
        author_name=args.author_name,
        socks_proxy=args.socks_proxy,
        http_proxy=args.http_proxy,
        timeout=timeout,
        github_url=args.api_url,
        no_sleep=args.no_sleep
    )

    if args.pull_request:
        if not args.branch:
            args.branch = 'main'

        gh_attack_runner.fork_pr_attack(
            args.target,
            args.branch,
            args.pr_title,
            args.source_branch,
            args.command,
            args.custom_file,
            args.message,
            args.file_name,
            args.name
        )

    elif args.workflow:
        gh_attack_runner.shell_workflow_attack(
            args.target,
            args.command,
            args.custom_file,
            args.branch,
            args.message,
            args.delete_action,
            args.file_name
        )
    elif args.secrets:
        gh_attack_runner.secrets_dump(
            args.target,
            args.branch,
            args.message,
            args.delete_action,
            args.file_name
        )


def enumerate(args, parser):
    parser = parser.choices["enumerate"]

    if not (args.target or args.self_enumeration or
            args.repository or args.repositories or args.validate or args.organizations):
        parser.error(
            f"{Fore.RED}[-]{Style.RESET_ALL} No enumeration type was"
            " specified!"
        )

    if sum(bool(x) for x in [args.target, args.self_enumeration,
                             args.repository, args.repositories,
                             args.validate, args.organizations]) != 1:
        parser.error(
            f"{Fore.RED}[-]{Style.RESET_ALL} You must only select one "
            "enumeration type."
        )

    gh_enumeration_runner = Enumerator(
            args.gh_token,
            socks_proxy=args.socks_proxy,
            http_proxy=args.http_proxy,
            output_yaml=args.output_yaml,
            skip_log=args.skip_runlog,
            github_url=args.api_url,
            no_sleep=args.no_sleep,
            wf_artifacts_enum=args.enum_wf_artifacts,
            skip_sh_runner_enum=args.skip_sh_runner_enum,
            include_all_artifact_secrets=args.include_all_artifact_secrets,

        )

    exec_wrapper = Execution()
    orgs = []
    repos = []

    if args.validate:
        orgs = gh_enumeration_runner.validate_only()
    elif args.self_enumeration:
        if gh_enumeration_runner.api.is_app_token():
            repos = gh_enumeration_runner.app_enumeration()
        else:
            orgs = gh_enumeration_runner.self_enumeration()
    elif args.target:
        orgs = [gh_enumeration_runner.enumerate_organization(
            args.target
        )]
    elif args.organizations:
        try:
            org_list = util.read_file_and_validate_lines(
                args.organizations, r"[A-Za-z0-9-_.]+"
            )
            orgs = []
            for org in org_list:
                orgs.append(gh_enumeration_runner.enumerate_organization(org))
        except argparse.ArgumentError as e:
            parser.error(
                f"{RED_DASH} The file contained an invalid organzation name!"
                f"{Output.bright(e)}"
            )
    elif args.repositories:
        try:
            repo_list = util.read_file_and_validate_lines(
                args.repositories,
                r"[A-Za-z0-9-_.]+\/[A-Za-z0-9-_.]+"
            )
            repos = gh_enumeration_runner.enumerate_repos(repo_list)
        except argparse.ArgumentError as e:
            parser.error(
                f"{RED_DASH} The file contained an invalid repository name!"
                f"{Output.bright(e)}"
            )
    elif args.repository:
        repos = [gh_enumeration_runner.enumerate_repo_only(
            args.repository
        )]

    exec_wrapper.set_user_details(gh_enumeration_runner.user_perms)
    exec_wrapper.add_organizations(orgs)
    exec_wrapper.add_repositories(repos)

    if args.output_json:
        Output.write_json(exec_wrapper, args.output_json)


def search(args, parser):
    parser = parser.choices["search"]

    gh_search_runner = Searcher(
        args.gh_token,
        socks_proxy=args.socks_proxy,
        http_proxy=args.http_proxy,
        github_url=args.api_url
    )
    if args.sourcegraph:
        if args.query and args.target:
            parser.error(
                f"{Fore.RED}[-]{Style.RESET_ALL} You cannot select an organization "
                "with a custom query!"
            )

        results = gh_search_runner.use_sourcegraph_api(
            organization=args.target,
            query=args.query
        )
    else:
        if not (args.query or args.target):
            parser.error(
                f"{Fore.RED}[-]{Style.RESET_ALL} You must select an organization "
                "or pass a custom query!."
            )
        if args.query:
            results = gh_search_runner.use_search_api(
                organization=args.target,
                query=args.query
            )
        else:
            results = gh_search_runner.use_search_api(
                organization=args.target
            )

    if results:
        gh_search_runner.present_results(results, args.output_text)


def configure_parser_general(parser):
    """Helper method to add arguments to all subarguments.

    Args:
        parser: The parser to add the arguments to.
    """
    parser.add_argument(
        "--socks-proxy", "-sp",
        help=(
            "SOCKS proxy to use for requests, in"
            f" {Fore.GREEN}HOST{Style.RESET_ALL}:{Fore.GREEN}PORT"
            f" {Style.RESET_ALL}format"
        ),
        required=False
    )

    parser.add_argument(
        "--http-proxy", "-p",
        help=(
            "HTTPS proxy to use for requests, in"
            f" {Fore.GREEN}HOST{Style.RESET_ALL}:{Fore.GREEN}PORT"
            f" {Style.RESET_ALL}format."
        ),
        required=False
    )

    parser.add_argument(
        "--supress", "-s",
        help="Supresses the ASCII art.",
        action='store_true'
    )

    parser.add_argument(
        "--no-color", "-nc",
        help="Removes all color from output.",
        action="store_true"
    )

    parser.add_argument(
        "--no-sleep",
        help="Exit immediately upon the API Rate Limit being hit.",
        action="store_true"
    )


def configure_parser_attack(parser):
    """Helper method to add arguments to the attack subparser.

    Args:
        parser: The parser to add attack subarguments to.
    """
    parser.add_argument(
        "--target", "-t",
        help="Repository to target in attack.",
        metavar="ORG/REPO",
        required=True,
        type=StringType(80)
    )

    parser.add_argument(
        "--author-name", "-a",
        help="Name of the author that all git commits will be made under.\n"
        "Defaults to the user associated with the PAT.",
        metavar="AUTHOR",
        type=StringType(256)
    )

    parser.add_argument(
        "--author-email", "-e",
        help="Email that all git commits will be made under.\n"
        "Defaults to the e-mail associated with the PAT.",
        metavar="EMAIL",
        type=StringType(256)
    )

    parser.add_argument(
        "--branch", "-b",
        metavar="BRANCH",
        help="Target branch for the attack.\n"
        "For a PR attack, this will be the branch on the target repo the PR\n"
        "will be made to. Defaults to 'main'.\n"
        "For a workflow attack, this will be the branch changes will be\n"
        "pushed to. This cannot be a pre-existing branch. Defaults to a random\n"
        "string.",
        type=StringType(244)
    )

    parser.add_argument(
        "--message", "-m",
        metavar="COMMIT_MESSAGE",
        help="Commit message to use. This is displayed in the Actions tab for\n"
             "workflow attacks. Defaults to 'Test Commit'",
        default="Test Commit",
        type=StringType(256)
    )

    parser.add_argument(
        "--command", "-c",
        help="Command to execute as part of payload. Defaults to 'whoami'"
    )

    parser.add_argument(
        "--workflow", "-w",
        help="Attack with a malicious workflow.",
        action="store_true"
    )

    parser.add_argument(
        "--pull-request", "-pr",
        help="Attack with a malicious pull request.",
        action="store_true",
    )

    parser.add_argument(
        "--secrets", "-sc",
        help="Attack to exfiltrate pipeline secrets.",
        action="store_true",
    )

    parser.add_argument(
        "--source-branch", "-sb",
        default="test",
        help="Name of the PR source branch, this will be displayed as\n"
             f"{Output.bright('user:branch_name')} when seen in the action approval\n"
             "page. Defaults to 'test'",
        type=StringType(244)
    )

    parser.add_argument(
        "--pr-title", "-pt",
        default="Test",
        help="Name of the PR that will be created. This will be displayed in\n"
             "the Actions tab and in the closed pull requests list once the\n"
             "tool quickly closes the PR. Defaults to 'Test'",
        metavar="NAME"
    )

    parser.add_argument(
        "--name", "-n",
        help="Name of the workflow. This will be shown in the actions tab.\n"
             "Defaults to 'test'",
        type=StringType(64)
    )

    parser.add_argument(
        "--file-name", "-fn",
        default="test",
        help=f"Name of yaml file {Output.bright('without extension')} that will be\n"
             "written as part of either attack type. Defaults to 'test'",
        type=StringType(64)
    )

    parser.add_argument(
        "--custom-file", "-f",
        help="Path to a yaml workflow that will be uploaded instead of a\n"
             "single shell command. A custom shell command or workflow name\n"
             "cannot be used with this option, as it is specified in the\n"
             "file. For fork PR attacks, you MUST include 'on': pull_request\n"
             "as a trigger, otherwise it will not work.",
        metavar="PATH/TO/FILE.YML",
        type=ReadableFile()
    )

    parser.add_argument(
        "--delete-action", "-d",
        help="Delete the resulting GitHub Action, if possible.",
        action="store_true",
    )

    parser.add_argument(
        "--timeout", "-to",
        metavar="SECONDS",
        help="Timeout, in seconds, to wait for the Action to queue and\n"
        "execute. For fork PR attacks, this is the time, in seconds, to wait "
        "for the fork repository to be created. Defaults to '30'",
        default="30",
        type=int
    )


def configure_parser_enumerate(parser):
    """Helper method to add arguments to the enumeration subparser.

    Args:
        parser: sub parser to add arguments to.
    """

    parser.add_argument(
        "--target", "-t",
        help="Target an organization to enumerate for self-hosted runners.",
        metavar=f"{Fore.RED}ORGANIZATION{Style.RESET_ALL}",
        type=StringType(39)
    )

    parser.add_argument(
        "--repository", "-r",
        help="Target a single repository in org/repo format to enumerate for\n"
        "self-hosted runners.",
        metavar=f"{Fore.RED}ORG/REPO_NAME{Style.RESET_ALL}",
        type=StringType(79, regex=r"[A-Za-z0-9-_.]+\/[A-Za-z0-9-_.]+")
    )

    parser.add_argument(
        "--organizations",
        "-O",
        help="A text file containing organizations to\n"
        "enumerate.",
        metavar=f"{Fore.RED}PATH/TO/FILE.txt{Style.RESET_ALL}",
        type=ReadableFile(),
    )

    parser.add_argument(
        "--repositories", "-R",
        help="A text file containing repositories in org/repo format to\n"
        "enumerate for self-hosted runners.",
        metavar=f"{Fore.RED}PATH/TO/FILE.txt{Style.RESET_ALL}",
        type=ReadableFile()
    )

    parser.add_argument(
        "--self-enumeration", "-s",
        help=(
            "Enumerate the configured token's access and all repositories or\n"
            "organizations the user has write access to that use self-hosted\n"
            "runners."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--validate", "-v",
        help=(
            "Validate if the token is valid and print organization memberships."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--enum_wf_artifacts",
        "-ewfa",
        help=("Retrieve workflow artifacts and scan for secrets."),
        action="store_true",
    )

    parser.add_argument(
        "--skip_sh_runner_enum",
        "-nosh",
        help=("Do not attempt to identify self-hosted runners."),
        action="store_true",
    )

    parser.add_argument(
        "--include_all_artifact_secrets",
        "-allas",
        help=("Artifact secrets scanning (--enum_wf_artifacts) filters out "
              "common false positives by default. Use this flag along with "
              "--enum_wf_artifacts to include all NoseyParker secrets results "
              "in artifacts."),
        action="store_true",
    )

    parser.add_argument(
        "--output-yaml", "-o",
        help=(
            "Directory to save gathered workflow yml files to. Will be\n"
            f"created in the following format: {Fore.GREEN}"
            f"org/repo/workflow.yml{Style.RESET_ALL}"
        ),
        metavar="DIR",
        type=WriteableDir()
    )

    parser.add_argument(
        "--skip-runlog", "-sr",
        help=(
            f"Do {Output.bright('NOT')} download any workflow run logs, this will\n"
            "speed up the enumeration, but may miss self-hosted runners for\n"
            "non-admin users."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--output-json", "-oJ",
        help=(
            "Save enumeration output to JSON file."
        ),
        metavar="JSON_FILE",
        type=StringType(256)
    )


def configure_parser_search(parser):
    """Helper method to add arguments to the search subparser.

    Args:
        parser: Add arguments to the search module subparser.
    """
    parser.add_argument(
        "--target", "-t",
        help="Organization to enumerate using GitHub code search.",
        metavar=f"{Fore.RED}ORGANIZATION{Style.RESET_ALL}",
        required=False,
    )

    parser.add_argument(
        "--query", "-q",
        help="Pass a custom query to GitHub code search",
        metavar="QUERY",
        required=False
    )

    parser.add_argument(
        "--sourcegraph", "-sg",
        help="Use Sourcegraph API to search for self-hosted runners.",
        required=False,
        action="store_true"
    )

    parser.add_argument(
        "--output-text", "-oT",
        help=(
            "Save enumeration output to text file."
        ),
        metavar="TEXT_FILE",
        type=StringType(256)
    )
