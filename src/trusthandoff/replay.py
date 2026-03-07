class ReplayProtection:
    """
    Minimal in-memory replay protection.

    Tracks packet nonces to prevent replay attacks.
    """

    def __init__(self):
        self._seen_nonces = set()

    def check_and_store(self, nonce: str) -> bool:
        """
        Returns True if nonce is new.
        Returns False if nonce was already seen.
        """

        if nonce in self._seen_nonces:
            return False

        self._seen_nonces.add(nonce)
        return True
