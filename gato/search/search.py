import logging

from gato.github import Search
from gato.github import Api

from colorama import Fore, Style
from gato.cli import (
    GREEN_PLUS,
    GREEN_EXCLAIM,
    YELLOW_EXCLAIM,
    RED_DASH,
    BRIGHT_DASH,
    bright,
)

logger = logging.getLogger(__name__)
logging.root.setLevel(logging.DEBUG)


class Searcher:
    """Class that encapsulates functionality to use the GitHub code search API.
    """

    def __init__(
        self,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
    ):
        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
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
                logger.error("This token cannot be used for enumeration!")
                return False

            print(
                f"{GREEN_PLUS} The authenticated user is:"
                f' {Style.BRIGHT}{self.user_perms["user"]}{Style.RESET_ALL}'
            )
            if len(self.user_perms["scopes"]) > 0:
                print(
                    f"{GREEN_PLUS} The GitHub Classic PAT has the following"
                    " scopes:"
                    f' {Fore.YELLOW}{", ".join(self.user_perms["scopes"])}'
                    f"{Style.RESET_ALL}!"
                )
            else:
                print(
                    f"{YELLOW_EXCLAIM} The token has no scopes!"
                )

        return True

    def use_search_api(self, organization: str):
        """Utilize GitHub Code Search API to try and identify repositories
        using self-hosted runners. This is subject to a high false-positive
        rate because any occurance of 'self-hosted' within a YAML file will
        yield a positive result. This is ideally used as a first line method to
        retrieve a list of candidate repos that can then be enumerated using
        methods like YAML parsing and action log analysis.

        Args:
            organization (str): Organization to enumerate using
            the GitHub code search API.

        Returns:
            list: List of repositories suspected of using self-hosted runners
            as identified by GitHub code search.
        """
        self.__setup_user_info()

        if not self.user_perms:
            return False

        api_search = Search(self.api)

        print(
            f"{YELLOW_EXCLAIM} Searching repositories within "
            f"{bright(organization)} using the GitHub Code Search API for"
            f" 'self-hosted' within YAML files."
        )
        candidates = api_search.search_enumeration(organization)

        print(
            f"{GREEN_PLUS} Identified {len(candidates)} non-fork "
            "repositories that matched the criteria!"
        )

        for candidate in candidates:
            print(candidate)
