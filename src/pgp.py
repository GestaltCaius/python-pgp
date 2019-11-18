from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def sign_message(msg: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Sign message using RSA algorithm
    :param msg: to sign
    :param private_key: RSA Private key used to sign `msg`
    :return: signed hash of `msg`
    """
    chosen_hash = hashes.SHA512()

    digest = hashes.Hash(chosen_hash, backend=default_backend())
    digest.update(msg)
    hash: bytes = digest.finalize()

    signed_hash: bytes = private_key.sign(
        hash,
        padding.PSS(
            mgf=padding.MGF1(chosen_hash),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash)
    )

    return signed_hash


def verify_message(msg: bytes, signed_hash: bytes, public_key: RSAPublicKey) -> bool:
    """
    Checks if signed_hash is truly msg's signed hash
    :param msg: original message
    :param signed_hash: hash to be checked
    :param public_key: RSA public key used to verify signature
    :return: True if signed_hash is msg hash signed by public_key's private key
    """
    chosen_hash = hashes.SHA512()

    digest = hashes.Hash(chosen_hash, default_backend())
    digest.update(msg)
    hash = digest.finalize()

    try:
        public_key.verify(
            signed_hash,
            hash,
            padding.PSS(
                mgf=padding.MGF1(chosen_hash),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            # chosen_hash
            utils.Prehashed(chosen_hash)
        )
    except InvalidSignature:
        return False
    return True
