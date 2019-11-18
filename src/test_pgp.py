from src.pgp import *
from src.user import *


class TestPgp:
    def test_signing(self):
        user = User()

        msg = b'Sign this please.'
        signed_hash = sign_message(msg, user.private_key)

        assert verify_message(msg, signed_hash, user.private_key.public_key()) is True
