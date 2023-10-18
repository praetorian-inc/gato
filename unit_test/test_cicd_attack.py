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
