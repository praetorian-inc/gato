# import os
# import pathlib
# import pytest
# import json
# import re

# from unittest.mock import patch
# from unittest.mock import MagicMock

# def test_assemble_repo_list():

#     mock_api = MagicMock()

#     mock_api.check_org_repos.return_value = [TEST_REPO_DATA]

#     gh_enumeration_runner = RepositoryEnum(
#         mock_api, False, True
#     )

#     repos = gh_enumeration_runner.__re

#     assert len(repos) == 1
#     assert repos[0].is_public() is True
