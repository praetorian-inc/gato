from gato.attack import CICDAttack


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
