from gato.github import Api

import time
import logging

logger = logging.getLogger(__name__)


class Search():
    """Search utility for GH api in order to find public repos that may have
    security issues.
    """

    def __init__(self, api_accessor: Api):
        """Initialize class to call GH search methods. Due to the late limiting
        associated with these API calls, this class will run the enumeration
        in a thread.


        Args:
            api_accesor (Api): API accesor to use when making GitHub
            API requests.
        """
        self.api_accessor = api_accessor

    def search_enumeration(self, organization: str):
        """Search for self-hosted in yml files within a given organization.

        Args:
            organization (str): Name of the github organization.

        Returns:
            set: Set containing repositories that are of interest.
        """

        query = {
            'q': f'self-hosted org:{organization} language:yaml',
            'sort': 'indexed',
            'per_page': '100',
            "page": 1
        }

        result = self.api_accessor.call_get('/search/code', params=query)
        if result.status_code == 200:
            query['page'] += 1
            code = result.json()
            candidates = []

            while len(code['items']) >= 1:
                for entry in code['items']:
                    # Only return non-forks
                    if ".github/workflows" in entry['path'] and \
                     not entry['repository']['fork']:
                        candidates.append(entry['repository']['full_name'])
                time.sleep(60)
                result = self.api_accessor.call_get(
                    '/search/code',
                    params=query
                )
                if result.status_code == 200:
                    query['page'] += 1
                    code = result.json()
                elif result.status_code == 403:
                    print(
                        '[-] Secondary rate limit hit! Sleeping 3 minutes!')
                    time.sleep(180)
                elif result.status_code == 422:
                    print('[-] Reached search cap!')
                    break

            return set(candidates)
        else:
            print('[-] Secondary rate limit hit!')
            # TODO: Check for auth issues here too!
            return set()
