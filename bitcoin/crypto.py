from hashlib import new, sha256 as _sha256

from coincurve import PrivateKey as ECPrivateKey, PublicKey as ECPublicKey

#using hashlib's sha256 function
def sha256(data):
    return _sha256(data).digest()

#using hashlib's ripemd160 function
def ripemd160(data):
    return new('ripemd160', data).digest()

def double_sha256_checksum(data):
    return sha256(sha256(data))[:4]

def ripemd160_sha256_checksum(data):
    return ripemd160(sha256(data))