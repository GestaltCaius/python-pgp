from src.user import *


class TestPgp:
    def test_signing(self):
        user = User()

        msg = b'Sign this please.'
        signed_hash = user.sign_message(msg)
        assert user.verify_message(msg, signed_hash, user.public_key) is True

    def test_aes_encrypt(self):
        pass

    def test_sending_pgp_key(self):
        pass
