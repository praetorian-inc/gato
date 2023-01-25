import requests
import os
import sys

reg_pat = os.environ.get('SH_RUNNER_MANAGE_TOKEN')
dispatch_pat = os.environ.get('WF_DISPATCH_TOKEN')
run_ref = os.environ.get('RUN_REF')


# Quick helper script for integration tests to get add/remove tokens.
if sys.argv[1] == 'remove':

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {reg_pat}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    response = requests.post(
        "https://api.github.com/orgs/GHRunnerPlayground/actions/runners/remove-token",
        headers=headers
    )
    if response.status_code == 201:
        token = response.json()['token']
        command = f"./config.sh remove --token {token} --name ghrunner-test"
        os.system(command)
elif sys.argv[1] == 'register':

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {reg_pat}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    response = requests.post(
        "https://api.github.com/orgs/GHRunnerPlayground/actions/runners/registration-token",
        headers=headers
    )

    if response.status_code == 201:
        token = response.json()['token']
        command = f"./config.sh --url https://github.com/GHRunnerPlayground --unattended --token {token} --name ghrunner-test"
        os.system(command)
elif sys.argv[1] == 'dispatch':

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {dispatch_pat}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    data = {
        "ref": run_ref
    }

    response = requests.post(
        "https://api.github.com/repos/praetorian-inc/gato/actions/workflows/integration_sh.yaml/dispatches",
        headers=headers,
        json=data
    )

    if response.status_code == 204:
        exit(0)
    else:
        exit(1)
elif sys.argv[1] == 'force_remove':
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {reg_pat}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    response = requests.get(
        "https://api.github.com/orgs/GHRunnerPlayground/actions/runners",
        headers=headers,
    )

    if response.status_code == 200:
        runner_info = response.json()

        runner = [runner for runner in runner_info['runners'] if
                  runner['name'] == 'ghrunner-test']

        if runner:
            remove_id = runner[0]['id']
            resp = requests.delete(
                f'https://api.github.com/orgs/GHRunnerPlayground/actions/runners/{remove_id}',
                headers=headers
            )

            if resp.status_code == 204:
                exit(0)
            else:
                exit(1)
