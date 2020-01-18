import logging
import os
import pickle
import random
import socket
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from pgp import PGP, PGPPacket, AESEncryptedData

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


class User(PGP):
    def __init__(self):
        PGP.__init__(self)
        self.user_id = random.randrange(42)

    def receive_secret_key(self, encrypted_key, sender_public_key) -> None:
        self._secret_key = self.receive_pgp_key(encrypted_key, sender_public_key)

    def join_room(self):
        pass

    def send_msg(self):
        pass


if __name__ == '__main__':
    host = "localhost"
    port = 15555
    user = User()
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        logger.info(f'User #{user.user_id} is connected to {host}:{port}')

        # Get secret key
        logger.info('Exchanging keys')
        pem = user.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        logger.info('Sending our public key')
        s.send(pem)
        server_public_key = s.recv(1024)

        logger.info("Loading server's public key")
        server_pem: RSAPublicKey = serialization.load_pem_public_key(
            server_public_key,
            backend=default_backend())

        pgp_packet = s.recv(4096)
        logger.info('Decrypting secret key using PGP')

        packet: PGPPacket = pickle.loads(pgp_packet)
        logger.debug(packet)

        user.receive_secret_key(packet, server_pem)

        logger.info('Secret key exchanged!')
        s.close()

        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            print('Type your message:\n')
            msg: bytes = input().encode('utf-8')

            logger.debug(f'Encrypting message: {msg}')
            iv = os.urandom(16)
            cipher_text = user.encrypt(msg, iv)

            packet: AESEncryptedData = AESEncryptedData(data=cipher_text, iv=iv)
            packet: bytes = pickle.dumps(packet)
            s.send(packet)
            s.close()
    except KeyboardInterrupt or EOFError:
        print('Exiting chat room!')
    finally:
        pass
