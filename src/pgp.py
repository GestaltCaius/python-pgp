import os
import zlib
from typing import List, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class PGP:
    def __init__(self):
        self.__private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.__secret_key: bytes = PGP.generate_secret_key()
        self.public_key = self.__private_key.public_key()

    def send_pgp_key(self, msg: str, receiver_public_key: RSAPublicKey) -> List[bytes]:
        """
        Send `msg` using PGP method
        :param msg: secret message
        :param receiver_public_key: receiver's public key
        :return: List containing encrypted message, signed hash and secret key. Message and hash also contain their IV.
        """
        # Sign message hash
        msg: bytes = msg.encode('utf-8')
        signed_hash: bytes = self.sign_message(msg)

        # Zip message and its signed hash
        message: List[bytes] = [msg, signed_hash]
        zipped_message: List[bytes] = [zlib.compress(m) for m in message]

        # Encrypt message (tuple of encrypted/IV)
        iv = os.urandom(16)
        encrypted_message: List = [(self.encrypt(m, self.__secret_key, iv), iv) for m in zipped_message]

        # Encrypt secret_key using receiver's public key
        encrypted_secret_key: bytes = receiver_public_key.encrypt(
            plaintext=self.__secret_key,
            padding=padding.OAEP(
                padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Add encrypted secret key to message
        encrypted_message.append(encrypted_secret_key)
        return encrypted_message

    def receive_pgp_key(self, encrypted_message: List[bytes], public_key: RSAPublicKey):
        # Get secret key used to encrypt message
        encrypted_secret_key: bytes = encrypted_message[2]
        secret_key: bytes = self.__private_key.decrypt(
            ciphertext=encrypted_secret_key,
            padding=padding.OAEP(
                padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt compressed message and its signed hash with secret key
        zipped_message = [self.decrypt(m[0], m[1], secret_key) for m in encrypted_message[0:2]]

        # Unzip (we get [Message, Hash])
        message = [zlib.decompress(m) for m in zipped_message]

        # Check signature
        if self.verify_message(message[0], message[1], public_key):
            return message[0]
        else:
            raise InvalidSignature

    def sign_message(self, plain_msg: bytes) -> bytes:
        """
        Sign message using RSA algorithm
        :param plain_msg: to sign
        :return: signed hash of `msg`
        """
        signed_hash = self.__private_key.sign(
            data=plain_msg,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
        return signed_hash

    def verify_message(self, msg: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
        """
        Checks message signature
        :param msg: message
        :param signature: message's signature
        :param public_key: sender's public key
        :return: true if signature is correct, false otherwise
        """
        try:
            public_key.verify(
                signature=signature,
                data=msg,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
        except InvalidSignature:
            return False
        return True

    def encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        from cryptography.hazmat.primitives import padding

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()

        return ct

    def decrypt(self, cipher_text: bytes, iv: bytes, key: bytes) -> bytes:
        from cryptography.hazmat.primitives import padding

        decryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()

        padded_data = decryptor.update(cipher_text) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()

        return data

    @classmethod
    def generate_secret_key(cls) -> bytes:
        """
        generates a 256bits key
        """
        return os.urandom(32)
