import argparse
import os
import re

from packaging import version

from gato.enumerate import Enumerator
from gato.attack import Attacker
from gato.search import Searcher

from gato import util
from gato.util.arg_utils import StringType
from gato.util.arg_utils import WriteableDir
from gato.util.arg_utils import ReadableFile
import gato.git as git

from gato.cli import bright
from gato.cli import Output

REQUIRED_GIT_VERSION = "2.27"


def cli(args):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            'This tool requires a GitHub PAT to function!\n\n'
            'This can be passed via the "GH_TOKEN" environment variable, or if'
            'it is not set,\nthen the application will prompt you for one.'
        ),
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    configure_parser_general(parser)

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

    output = Output(arguments.silent, not arguments.no_color)

    validate_arguments(arguments, parser, output)
    validate_git_config(parser, output)

    arguments.func(arguments, subparsers, output)


def validate_arguments(args, parser, output):
    if "GH_TOKEN" not in os.environ:
        gh_token = input(
            "No 'GH_TOKEN' environment variable set! Please enter a GitHub"
            " PAT.\n"
        )
    else:
        gh_token = os.environ["GH_TOKEN"]

    if "github_pat_" in gh_token:
        output.error("Fine-grained PATs are currently not supported!", parser)

    if not ("ghp_" in gh_token or "gho_" in gh_token or "ghu_" in
            gh_token or re.match('^[a-fA-F0-9]{40}$', gh_token)):
        output.error(f"Provided GitHub PAT is malformed!", parser)

    args_dict = vars(args)
    args_dict["gh_token"] = gh_token

    if args.socks_proxy and args.http_proxy:
        output.error("You cannot use a SOCKS and HTTP proxy at the same time!",
                     parser)


def validate_git_config(parser, output):
    git_status = git.path_check()
    if not git_status:
        output.error(
                "The 'git' application is either not installed, or not present on "
                "the path!",
                parser
        )

    git_version = git.version_check()

    if git_version:
        git_version = version.parse(git_version)
        if git_version < version.parse(REQUIRED_GIT_VERSION):
            output.error(
                "This tool requires a 'git' version of at least "
                f"{REQUIRED_GIT_VERSION}!",
                parser
            )
    else:
        output.error("'git --version' returned unexpected output!", parser)


def attack(args, parser, output):
    parser = parser.choices["attack"]
    if not (args.workflow != args.pull_request):
        output.error("You must select one of the attack modes (workflow or pr)!",
                     parser)

    if args.custom_file and (args.command or
                             args.name):
        output.error("A shell command or workflow name cannot be used with a"
                     " custom workflow.",
                     parser)

    if not args.custom_file:
        args.command = args.command if args.command else "whoami"
        args.name = args.name if args.name else "test"

    timeout = int(args.timeout)

    output.splash()

    gh_attack_runner = Attacker(
        output,
        args.gh_token,
        author_email=args.author_email,
        author_name=args.author_name,
        socks_proxy=args.socks_proxy,
        http_proxy=args.http_proxy,
        timeout=timeout
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


def enumerate(args, parser, output):
    parser = parser.choices["enumerate"]

    if not (args.target or args.self_enumeration or
            args.repository or args.repositories):
        output.error("No enumeration type was specified!", parser)

    if sum(bool(x) for x in [args.target, args.self_enumeration,
                             args.repository, args.repositories]) != 1:
        output.error("You must only select one enumeration type.", parser)

    if args.skip_clones and args.output_yaml:
        output.error("Cannot output ymls if cloning is not enabled!", parser)

    output.splash()

    gh_enumeration_runner = Enumerator(
            output,
            args.gh_token,
            socks_proxy=args.socks_proxy,
            http_proxy=args.http_proxy,
            skip_clones=args.skip_clones,
            output_yaml=args.output_yaml,
            skip_log=args.skip_runlog,
        )

    if args.self_enumeration:
        gh_enumeration_runner.self_enumeration()
    elif args.target:
        gh_enumeration_runner.enumerate_organization(
            args.target
        )
    elif args.repositories:
        try:
            repo_list = util.read_file_and_validate_lines(
                args.repositories,
                r"[A-Za-z0-9-_.]+\/[A-Za-z0-9-_.]+"
            )
            gh_enumeration_runner.enumerate_repos(repo_list)
        except argparse.ArgumentError as e:
            output.error(
                f"The file contained an invalid repository name! {bright(e)}",
                parser
            )
    elif args.repository:
        gh_enumeration_runner.enumerate_repo_only(args.repository)


def search(args, parser, output):
    parser = parser.choices["search"]

    gh_search_runner = Searcher(
        output,
        args.gh_token,
        socks_proxy=args.socks_proxy,
        http_proxy=args.http_proxy
    )

    output.splash()

    gh_search_runner.use_search_api(args.target)


def configure_parser_general(parser):
    """Helper method to add arguments to all subarguments.

    Args:
        parser: The parser to add the arguments to.
    """
    parser.add_argument(
        "--socks-proxy", "-sp",
        help="SOCKS proxy to use for requests, in HOST:PORT format",
        required=False
    )

    parser.add_argument(
        "--http-proxy", "-p",
        help="HTTPS proxy to use for requests, in HOST:PORT format",
        required=False
    )

    parser.add_argument(
        "--silent", "-s",
        help="Reduces output to minimal information and removes ASCII arts.",
        action='store_true'
    )

    parser.add_argument(
        "--no-color", "-nc",
        help="Removes all color from output.",
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
        "--source-branch", "-sb",
        default="test",
        help="Name of the PR source branch, this will be displayed as\n"
             f"{bright('user:branch_name')} when seen in the action approval\n"
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
        help=f"Name of yaml file {bright('without extension')} that will be\n"
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
        metavar="ORGANIZATION",
        type=StringType(39)
    )

    parser.add_argument(
        "--repository", "-r",
        help="Target a single repository in org/repo format to enumerate for\n"
        "self-hosted runners.",
        metavar="ORG/REPO_NAME",
        type=StringType(79, regex=r"[A-Za-z0-9-_.]+\/[A-Za-z0-9-_.]+")
    )

    parser.add_argument(
        "--repositories", "-R",
        help="A text file containing repositories in org/repo format to\n"
        "enumerate for self-hosted runners.",
        metavar="PATH/TO/FILE.txt",
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
        "--output-yaml", "-o",
        help=(
            "Directory to save gathered workflow yml files to. Will be\n"
            "created in the following format: org/repo/workflow.yml"
        ),
        metavar="DIR",
        type=WriteableDir()
    )

    parser.add_argument(
        "--skip-clones", "-sc",
        help=(
            f"Do {bright('NOT')} perform any git clone operations as part of\n"
            "enumeration, as this generates log events for GitHub Enterprise\n"
            "Cloud customers."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--skip-runlog", "-sr",
        help=(
            f"Do {bright('NOT')} download any workflow run logs, this will\n"
            "speed up the enumeration, but may miss self-hosted runners for\n"
            "non-admin users."
        ),
        action="store_true",
    )


def configure_parser_search(parser):
    """Helper method to add arguments to the search subparser.

    Args:
        parser: Add arguments to the search module subparser.
    """
    parser.add_argument(
        "--target", "-t",
        help="Organization to enumerate using GitHub code search.",
        metavar="ORGANIZATION",
        required=True,
    )
