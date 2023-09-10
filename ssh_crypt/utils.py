import os
import binascii
import logging

from pathlib import Path
from typing import Union, Optional

from paramiko import Agent
from paramiko import AgentKey
from paramiko.pkey import PKey
from paramiko import RSAKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.agent import cSSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENT_IDENTITIES_ANSWER

from .ciphers import Decryptor
from .constants import VALID_SSH_NAME
from .exceptions import (
    SSHCrypAgentNotConnected,
    SSHCryptCannotRetrieveKeysError,
    SSHCryptFileError,
)


logger = logging.getLogger(__name__)


def get_keys(agent: Agent | None = None) -> list[AgentKey]:
    """retrieves a list of agent keys"""
    agent = agent or Agent()

    # this is the only reliable way to check if there's a connection
    # (see paramiko.agent.Agent.__init__)
    if not agent._conn:
        raise SSHCrypAgentNotConnected(
            "no connection to an ssh agent",
            "is ssh-agent running? is SSH_AUTH_SOCK set?",
        )
    ptype, result = agent._send_message(cSSH2_AGENTC_REQUEST_IDENTITIES)
    if ptype != SSH2_AGENT_IDENTITIES_ANSWER:
        raise SSHCryptCannotRetrieveKeysError(
            "could not get keys from ssh-agent",
            f"check SSH_AUTH_SOCK={os.getenv('SSH_AUTH_SOCK')} "
            f"or SSH_AGENT_PID={os.getenv('SSH_AGENT_PID')} are"
            f" pointing to the right agent and they are running",
        )
    keys = []
    for i in range(result.get_int()):
        key_blob = result.get_binary()
        key_comment = result.get_string()
        keys.append((AgentKey(agent, key_blob), key_comment))
    return keys


def create_new_key_pair(
    ssh_name: str,
    dest: Path | None = None,
    force: bool = False,
    password: str | None = None,
    **kwargs,
) -> tuple[PKey, Path]:
    assert ssh_name in VALID_SSH_NAME

    home = Path(os.getenv("SSH_HOME") or "~/.ssh").expanduser()
    path = home / (
        dest
        or {
            "ssh-rsa": "id_rsa",
            "ssh-ed25519": "id_ed25519",
        }[ssh_name]
    )

    logger.debug(
        "writing private(public) keys under %s(%s)", path, path.with_suffix(".pub")
    )

    if ssh_name == "ssh-rsa":
        if "bits" not in kwargs:
            kwargs["bits"] = 2048
        key = RSAKey.generate(**kwargs)
    elif ssh_name == "ssh-ed25519":
        key = ECDSAKey.generate(**kwargs)

    if not force and (path.exists() or path.with_suffix(".pub").exists()):
        raise SSHCryptFileError("key file(s) present", f"remove {path}(.pub)?")

    path.parent.mkdir(parents=True, exist_ok=True)
    key.write_private_key_file(path, password)
    path.with_suffix(".pub").write_text(f"{key.get_name()} {key.get_base64()}")

    return key, path


def get_first_key():
    # Only RSA and ED25519 keys have capability to get
    # the same sign data from same nonce
    keys = get_keys()
    keys = [key for key in keys if key[0].name in VALID_SSH_NAME]
    if keys:
        return keys[0][0]


def find_filter_key(ssh_filter):
    ssh_filter = ssh_filter.encode()
    filter_keys = []
    for key in [key for key in get_keys() if key[0].name in VALID_SSH_NAME]:
        if ssh_filter in key[1]:
            filter_keys.append(key)
        elif ssh_filter in binascii.hexlify(key[0].get_fingerprint(), sep=":"):
            filter_keys.append(key)
    if filter_keys:
        return filter_keys[0][0]


class E:
    def __init__(
        self,
        data: Union[str, bytes],
        binary=False,
        key: Optional[str] = None,
        ssh_key: Optional[AgentKey] = None,
    ):
        if ssh_key:
            self.ssh_key = ssh_key
        if key:
            self.ssh_key = find_filter_key(key)
        if not key:
            self.ssh_key = get_first_key()

        if isinstance(data, str):
            data = data.encode("utf-8")
        self.data = data

    def __bytes__(self) -> bytes:
        ssh_key = get_first_key()

        decryptor = Decryptor(ssh_key, binary=False)
        return decryptor.send(self.data) + decryptor.send(b"")

    def __str__(self) -> str:
        return self.__bytes__().decode("utf-8")
