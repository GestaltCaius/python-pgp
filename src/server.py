import json
import logging
import os
import pickle
import select
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


class Server(PGP):

    def __init__(self):
        PGP.__init__(self)
        self.connection_list = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('', 15555))
        self.server_socket.listen(5)
        self.connection_list.append(self.server_socket)

    def send_secret_key(self, receiver_public_key):
        return self.send_pgp_key(self._secret_key, receiver_public_key)

    def broadcast_msg(self, sender_socket, msg):
        # Do not send the message to master socket and the client who has send us the message
        for s in self.connection_list:
            if s is not self.server_socket and s is not sender_socket:
                try:
                    s.send(msg)
                except KeyboardInterrupt:
                    s.close()
                    self.connection_list.remove(s)


if __name__ == '__main__':
    server = Server()
    server_pem = server.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    try:
        while True:
            read_sockets, write_sockets, error_sockets = select.select(server.connection_list, [], [])
            for s in read_sockets:
                # New connection
                if s is server.server_socket:
                    # New connection
                    new_client_socket, addr = s.accept()
                    server.connection_list.append(new_client_socket)
                    logger.info(f"Client ({addr}) connected")
                    iv = os.urandom(16)
                    cipher_text = server.encrypt(f"Client ({addr}) is offline".encode('utf-8'), iv)
                    msg = AESEncryptedData(data=cipher_text, iv=iv)
                    msg = SecretMessage(op_code=OP_CODE_MSG, data=msg, user_id=-1)
                    msg = pickle.dumps(msg)
                    server.broadcast_msg(new_client_socket, msg)

                # Some incoming message from a client
                else:
                    # Data recieved from client, process it
                    try:
                        # In Windows, sometimes when a TCP program closes abruptly,
                        # a "Connection reset by peer" exception will be thrown
                        raw_response: bytes = s.recv(4096)
                        if raw_response == b'':
                            continue
                        response: SecretMessage = pickle.loads(raw_response)
                        op_code = response['op_code']
                        if op_code == OP_CODE_KEY:
                            logger.info(f"Sending server public key to user {response['user_id']}")
                            s.send(server_pem)

                            logger.info('Creating PGP packet to send secret key to client')
                            client_public_key: RSAPublicKey = serialization.load_pem_public_key(
                                response['data'],
                                backend=default_backend())
                            encrypted_pgp_key: PGPPacket = server.send_secret_key(client_public_key)
                            msg = pickle.dumps(encrypted_pgp_key)

                            logger.info('Sending PGP packet to client')
                            s.send(msg)

                        elif op_code == OP_CODE_MSG:
                            logger.info(f'Received encrypted message from user {response["user_id"]}')
                            server.broadcast_msg(s, raw_response)
                    except KeyboardInterrupt:
                        iv = os.urandom(16)
                        cipher_text = server.encrypt(f"Client ({addr}) is offline".encode('utf-8'), iv)
                        msg = AESEncryptedData(data=cipher_text, iv=iv)
                        msg = SecretMessage(op_code=OP_CODE_MSG, data=msg, user_id=-1)
                        msg = pickle.dumps(msg)
                        server.broadcast_msg(s, msg)
                        logger.info(f"Client ({addr}) is now offline")
                        s.close()
                        server.connection_list.remove(s)
                        continue
    except KeyboardInterrupt:
        logger.info('Shutting down server...')
    finally:
        server.server_socket.close()

