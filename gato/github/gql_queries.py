class GqlQueries():
    """Constructs graphql queries for use with the GitHub GraphQL api.
    """

    GET_YMLS = """
        query RepoFiles($node_ids: [ID!]!) {
        nodes(ids: $node_ids) {
            ... on Repository {
            nameWithOwner
            object(expression: "HEAD:.github/workflows/") {
                ... on Tree {
                entries {
                    name
                    type
                    mode
                    object {
                    ... on Blob {
                        byteSize
                        text
                    }
                    }
                }
                }
            }
            }
        }
        }
    """

    @staticmethod
    def get_workflow_ymls(repos: list):
        """Retrieve workflow yml files for each repository.

        Args:
            repos (List[Repository]): List of repository objects
        Returns:
            (list): List of JSON post parameters for each graphQL query.
        """
        queries = []

        for i in range(0, (len(repos) // 100) + 1):

            top_len = len(repos) if len(repos) < (100 + i*100) else (100 + i*100)
            query = {
                "query": GqlQueries.GET_YMLS,
                "variables": {
                    "node_ids": [repo.repo_data['node_id'] for repo in repos[0+100*i:top_len]]
                }
            }

            queries.append(query)
        return queries
