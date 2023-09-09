class SSHCryptError(Exception):
    def __init__(self, message, hint=""):
        self.message = message
        self.hint = hint
        super().__init__()


class SSHCrypAgentNotConnected(SSHCryptError):
    pass


class SSHCryptCannotRetrieveKeysError(SSHCryptError):
    pass
