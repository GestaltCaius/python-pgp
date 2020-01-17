from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from .pgp import PGP


class User(PGP):
    def __init__(self):
        PGP.__init__(self)

    def receive_secret_key(self, encrypted_key, sender_public_key):
        return self.receive_pgp_key(encrypted_key, sender_public_key)

    def join_room(self):
        pass

    def send_msg(self):
        pass
