import json
import logging
import pickle
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from pgp import PGP, PGPPacket, AESEncryptedData
import socket

from secret_message import *

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


class JSONBytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            return obj.decode('ASCII')
        return json.JSONEncoder.default(self, obj)


class Server(PGP):
    def send_secret_key(self, receiver_public_key):
        return self.send_pgp_key(self._secret_key, receiver_public_key)


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 15555))

    server = Server()
    server_pem = server.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    try:
        while True:
            s.listen(5)
            client, address = s.accept()
            print("{} connected".format(address))

            logger.info('Waiting for client messages')
            response: bytes = client.recv(4096)
            response: SecretMessage = pickle.loads(response)

            op_code = response['op_code']
            if op_code == OP_CODE_KEY:
                logger.info(f"Sending server public key to user {response['user_id']}")
                client.send(server_pem)

                logger.info('Creating PGP packet to send secret key to client')
                client_public_key: RSAPublicKey = serialization.load_pem_public_key(
                    response['data'],
                    backend=default_backend())
                encrypted_pgp_key: PGPPacket = server.send_secret_key(client_public_key)
                msg = pickle.dumps(encrypted_pgp_key)

                logger.info('Sending PGP packet to client')
                client.send(msg)
            elif op_code == OP_CODE_MSG:
                logger.info(f'Received encrypted message from user {response["user_id"]}')
                encrypted_msg: AESEncryptedData = response['data']
                logger.info(f"User#{response['user_id']}: {server.decrypt(encrypted_msg['data'], encrypted_msg['iv'])}")
    except KeyboardInterrupt:
        logger.info('Shutting down server...')
    finally:
        s.close()
