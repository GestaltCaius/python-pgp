from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


class User:
    def __init__(self):
        self.__secret_key = None

    def join_room(self):
        pass

    def send_msg(self):
        pass
