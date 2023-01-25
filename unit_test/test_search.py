from unittest.mock import patch, MagicMock
from gato.github.search import Search
from gato.search import Searcher


@patch("gato.github.search.time.sleep")
@patch("gato.github.search.Api")
def test_search_api(mock_api, mock_time):

    mock_api.call_get.return_value.status_code = 200

    mock_api.call_get.return_value.json.side_effect = [{
        "items": [
            {
                "path": ".github/workflows/yaml_wf.yml",
                "repository": {
                    "fork": False,
                    "full_name": 'testOrg/testRepo'
                },
            }
        ]
    }, {
        "items": []
    }]

    searcher = Search(mock_api)

    res = searcher.search_enumeration('testOrganization')
    assert len(res) == 1
    assert 'testOrg/testRepo' in res


@patch("gato.github.search.time.sleep")
@patch("gato.github.search.Api")
def test_search_api_cap(mock_api, mock_time, capfd):

    mock1 = MagicMock()
    mock1.status_code = 200

    mock1.json.return_value = {
        "items": [
            {
                "path": ".github/workflows/yaml_wf.yml",
                "repository": {
                    "fork": False,
                    "full_name": 'testOrg/testRepo'
                },
            }
        ]
    }

    mock2 = MagicMock()
    mock2.status_code = 422

    mock_api.call_get.side_effect = [mock1, mock2]

    searcher = Search(mock_api)

    res = searcher.search_enumeration('testOrganization')
    mock_time.assert_called_once()
    assert len(res) == 1
    out, err = capfd.readouterr()
    assert "[-] Reached search cap!" in out


@patch("gato.github.search.time.sleep")
@patch("gato.github.search.Api")
def test_search_api_ratelimit(mock_api, mock_time, capfd):

    mock1 = MagicMock()
    mock1.status_code = 200

    mock1.json.return_value = {
        "items": [
            {
                "path": ".github/workflows/yaml_wf.yml",
                "repository": {
                    "fork": False,
                    "full_name": 'testOrg/testRepo'
                },
            }
        ]
    }

    mock2 = MagicMock()
    mock2.status_code = 403

    mock3 = MagicMock()
    mock3.status_code = 200
    mock3.json.return_value = {"items": []}

    mock_api.call_get.side_effect = [mock1, mock2, mock3]

    searcher = Search(mock_api)

    res = searcher.search_enumeration('testOrganization')
    assert mock_time.call_count == 3
    assert len(res) == 1

    out, err = capfd.readouterr()
    assert "[-] Secondary rate limit hit! Sleeping 3 minutes!" in out


@patch('gato.github.Search.search_enumeration')
@patch("gato.search.search.Api")
def test_search(mock_api, mock_search):
    mock_search.return_value = ['candidate1', 'candidate2']
    gh_search_runner = Searcher('ghp_AAAA')

    res = gh_search_runner.use_search_api('targetOrg')
    mock_search.assert_called_once()
    assert res is not False


@patch("gato.search.search.Api.check_user")
def test_search_bad_token(mock_api):
    mock_api.return_value = False
    gh_search_runner = Searcher('ghp_AAAA')

    res = gh_search_runner.use_search_api('targetOrg')
    assert res is False
