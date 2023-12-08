import logging
import requests
import json

from gato.github import Search
from gato.github import Api

from gato.cli import Output

logger = logging.getLogger(__name__)


class Searcher:
    """Class that encapsulates functionality to use the GitHub code search API.
    """

    def __init__(
        self,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        github_url: str = None,
    ):
        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
            github_url=github_url,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.user_perms = None

    def __setup_user_info(self):
        """Checks the PAT to ensure that it is valid and retrieves the
        associated scopes.

        Returns:
            bool: If the PAT is associated with a valid user.
        """
        if not self.user_perms:
            self.user_perms = self.api.check_user()
            if not self.user_perms:
                Output.error("This token cannot be used for enumeration!")
                return False

            Output.info(
                f"The authenticated user is: "
                f"{Output.bright(self.user_perms['user'])}"
            )
            if len(self.user_perms["scopes"]) > 0:
                Output.info(
                    f"The GitHub Classic PAT has the following scopes: "
                    f'{Output.yellow(", ".join(self.user_perms["scopes"]))}'
                )
            else:
                Output.warn("The token has no scopes!")

        return True

    def use_sourcegraph_api(
            self,
            organization: str,
            query=None,
            output_text=None):
        """
        This method is used to search for repositories in an organization using the Sourcegraph API.
        It constructs a search query and sends a GET request to the Sourcegraph search API.
        The results are streamed and added to a set.

        Args:
            organization (str): The name of the organization to search in.
            query (str, optional): A custom search query. If not provided, a default query is used.
            output_text (str, optional): The file path where the results should be written. Defaults to None.

        Returns:
            set: A set of search results.
        """
        repo_filter = f"repo:{organization}/ " if organization else ""
        url = "https://sourcegraph.com/.api/search/stream"
        headers = {"Content-Type": "application/json"}
        params = {
            "q": (
                "('self-hosted' OR "
                "(/runs-on/ AND NOT "
                "/(ubuntu-16.04|ubuntu-18.04|ubuntu-20.04|ubuntu-22.04|ubuntu-latest|"
                "windows-2019|windows-2022|windows-latest|macos-11|macos-12|macos-13|"
                "macos-12-xl|macos-13-xl|macos-latest|matrix.[a-zA-Z]\\s)/)) "
                f"{repo_filter}"
                "lang:YAML file:.github/workflows/ count:30000"
            )
        }
        if query:
            Output.info(
                f"Searching SourceGraph with the following query: {Output.bright(query)}"
            )
            params["q"] = query
        else:
            Output.info(
                f"Searching SourceGraph with the default Gato query: {Output.bright(params['q'])}"
            )
        response = requests.get(url, headers=headers, params=params, stream=True)
        results = set()

        if response.status_code == 200:
            for line in response.iter_lines():
                if line and line.decode().startswith("data:"):
                    json_line = line.decode().replace("data:", "").strip()
                    event = json.loads(json_line)
                    for element in event:
                        if "repository" in element:
                            results.add(
                                element["repository"].replace("github.com/", "")
                            )

        Output.result(
            f"Identified {len(results)} non-fork repositories that matched "
            "the criteria!"
        )
        if output_text:
            with open(output_text, "w") as file_output:
                for candidate in results:
                    file_output.write(f"{candidate}\n")

        for candidate in results:
            Output.tabbed(candidate)

    def use_search_api(self, organization: str, query=None, output_text=None):
        """Utilize GitHub Code Search API to try and identify repositories
        using self-hosted runners. This is subject to a high false-positive
        rate because any occurance of 'self-hosted' within a YAML file will
        yield a positive result. This is ideally used as a first line method to
        retrieve a list of candidate repos that can then be enumerated using
        methods like YAML parsing and action log analysis.

        Args:
            organization (str): Organization to enumerate using
            the GitHub code search API.
            query (str, optional): Custom code-search query.
            output_text(str, optional): Path to output text file.

        Returns:
            list: List of repositories suspected of using self-hosted runners
            as identified by GitHub code search.
        """
        self.__setup_user_info()

        if not self.user_perms:
            return False

        api_search = Search(self.api)

        if query:
            Output.info(
                f"Searching GitHub with the following query: {Output.bright(query)}"
            )
        else:
            Output.info(
                f"Searching repositories within {Output.bright(organization)} "
                "using the GitHub Code Search API for 'self-hosted' within "
                "YAML files."
            )
        candidates = api_search.search_enumeration(
            organization, custom_query=query
        )

        Output.result(
            f"Identified {len(candidates)} non-fork repositories that matched "
            "the criteria!"
        )

        if output_text:
            with open(output_text, "w") as file_output:
                for candidate in candidates:
                    file_output.write(f"{candidate}\n")

        for candidate in candidates:
            Output.tabbed(candidate)

    def present_results(self, results, output_text=None):
        """
        This method is used to present the results of the search. It first
        prints the number of non-fork repositories that matched the criteria.
        If an output_text file path is provided, it writes the results into
        that file. Finally, it prints each result in a tabbed format.

        Args:
            results (list): A list of non-fork repositories that matched the
            criteria.
            output_text (str, optional): The file path where the results
            should be written. Defaults to None.
        """
        Output.result(
            f"Identified {len(results)} non-fork repositories that matched "
            "the criteria!"
        )

        if output_text:
            with open(output_text, "w") as file_output:
                for candidate in results:
                    file_output.write(f"{candidate}\n")

        for candidate in results:
            Output.tabbed(candidate)
