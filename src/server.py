from .pgp import PGP


class Server(PGP):
    def send_secret_key(self, receiver_public_key):
        return self.send_pgp_key(self._secret_key, receiver_public_key)
