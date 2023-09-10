import os
import sys
from pathlib import Path
import pytest

import ssh_crypt
from ssh_crypt import exceptions, utils


def test_get_keys_missing_agent(monkeypatch):
    """test failure to connect to an agent"""

    # make sure we don't connect to any ssh agent
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    monkeypatch.delenv("SSH_AGENT_PID", raising=False)
    pytest.raises(exceptions.SSHCrypAgentNotConnected, ssh_crypt.E, "Hello world")
    pytest.raises(exceptions.SSHCrypAgentNotConnected, utils.get_keys)


@pytest.mark.skipif(sys.platform.startswith("win"), reason="cannot run this on windows")
def test_create_new_key_pair(ssh_agent, ssh_add):
    assert ssh_agent

    password = "hello-world-password"

    # creates two keys one password protected
    assert len(utils.get_keys()) == 0
    paths = []
    paths.append(utils.create_new_key_pair("ssh-rsa")[1])
    paths.append(utils.create_new_key_pair("ssh-ed25519", password=password)[1])
    for path in paths:
        assert path.is_relative_to(Path(os.getenv("SSH_HOME")))
        ssh_add(path, password)
    assert len(utils.get_keys()) == 2
