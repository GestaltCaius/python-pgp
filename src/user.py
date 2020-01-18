import logging
import os
import pickle
import random
import select
import socket
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from pgp import PGP, PGPPacket, AESEncryptedData
from secret_message import *

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

    def prompt(self):
        sys.stdout.write('Type your message: ')
        sys.stdout.flush()


if __name__ == '__main__':
    host = "localhost"
    port = 15555
    user = User()
    try:
        # Create socket
        user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        user_socket.settimeout(2)
        user_socket.connect((host, port))
        logger.info(f'User #{user.user_id} is connected to {host}:{port}')

        # Get secret key
        logger.info('Exchanging keys')
        pem = user.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        logger.info('Sending our public key')
        msg = SecretMessage(op_code=OP_CODE_KEY, data=pem, user_id=user.user_id)
        msg = pickle.dumps(msg)
        user_socket.send(msg)
        server_public_key = user_socket.recv(4096)

        logger.info("Loading server's public key")
        server_pem: RSAPublicKey = serialization.load_pem_public_key(
            server_public_key,
            backend=default_backend())

        pgp_packet = user_socket.recv(4096)
        logger.info('Decrypting secret key using PGP')

        packet: PGPPacket = pickle.loads(pgp_packet)
        logger.debug(packet)

        user.receive_secret_key(packet, server_pem)

        logger.info('Secret key exchanged!')

        while True:
            socket_list = [sys.stdin, user_socket]
            # Get the list sockets which are readable
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])
            for s in read_sockets:
                # incoming message from remote server
                if s is user_socket:
                    data = user_socket.recv(4096)
                    if not data:
                        logger.info('Disconnected from chat server')
                        sys.exit()
                    else:
                        # print data
                        data: SecretMessage = pickle.loads(data)
                        data: AESEncryptedData = data['data']
                        msg = user.decrypt(data['data'], data['iv'])
                        sys.stdout.write(msg.decode('utf-8'))
                        user.prompt()
                # user entered a message
                else:
                    msg = sys.stdin.readline()

                    logger.debug(f'Encrypting message: {msg}')
                    iv = os.urandom(16)
                    cipher_text = user.encrypt(msg.encode('utf-8'), iv)
                    msg = AESEncryptedData(data=cipher_text, iv=iv)
                    msg = SecretMessage(op_code=OP_CODE_MSG, data=msg, user_id=user.user_id)
                    msg = pickle.dumps(msg)
                    user_socket.send(msg)
                    user.prompt()
    except KeyboardInterrupt or EOFError:
        print('Exiting chat room!')
        user_socket.close()
    finally:
        pass
