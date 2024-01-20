#signing key specifics for ethereum using python

from ecdsa import SigningKey, SECP256k1 as ECDSASigningKey, SECP256k1
from ecdsa.util import sigencode_der, sigdecode_der
from hashlib import sha256

class SigningKey:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.ecdsa = ECDSASigningKey.from_string(raw, curve=SECP256k1)

    def private_key(self) -> bytes:
        return self.private_key

    def public_key(self) -> bytes:
        return self.ecdsa.verifying_key.to_string()

    def compressed_public_key(self) -> bytes:
        return self.ecdsa.verifying_key.to_string('compressed')

    def sign(self, message: bytes) -> bytes:
        return self.ecdsa.sign(message, hashfunc=sha256, sigencode=sigencode_der)

    #compute the public key from the private key
    def recover_public_key(self, message: bytes, signature: bytes) -> bytes:
        return self.ecdsa.recover_public_key_from_signature(message, signature, hashfunc=sha256)

    def recover_private_key(digest: bytes, signature: bytes) -> bytes:
        assert len(signature) == 65, 'invalid signature length'
        sig = datatypes.signature(signature)
        secp_sig = ecdsa.util.sigdecode_der(sig, SECP256k1.order)
        return secp_sig

    def add_points(p0: bytes, p1: bytes) -> bytes:
        p0 = ecdsa.ellipticcurve.Point(SECP256k1.curve, *p0)
        p1 = ecdsa.ellipticcurve.Point(SECP256k1.curve, *p1)
        p = p0 + p1
        return p.x(), p.y()