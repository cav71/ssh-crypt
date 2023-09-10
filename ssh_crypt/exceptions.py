class SSHCryptError(Exception):
    pass


class SSHCrypAgentNotConnected(SSHCryptError):
    pass


class SSHCryptCannotRetrieveKeysError(SSHCryptError):
    pass


class SSHCryptFileError(SSHCryptError):
    pass
