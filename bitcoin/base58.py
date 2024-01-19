from collections import deque

from bitcoin.crypto import double_sha256_checksum
from bitcoin.utils import int_to_unknown_bytes

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(b):
    """Encode bytes to a base58-encoded string"""
    if not b:
        return ''
    n = int.from_bytes(b, 'big')
    s = []
    while n > 0:
        n, r = divmod(n, 58)
        s.append(BASE58_ALPHABET[r])
    return ''.join(reversed(s))

def base58_decode(s):  
    """Decode a base58-encoded string to bytes"""
    if not s:
        return b''
    n = 0
    for c in s:
        n *= 58
        if c not in BASE58_ALPHABET:
            raise ValueError("Character %r is not a valid base58 character" % c)
        digit = BASE58_ALPHABET.index(c)
        n += digit
    return int_to_unknown_bytes(n)

def base58_check_encode(b, version):
    """Encode bytes to a base58-check-encoded string"""
    return base58_encode(b + double_sha256_checksum(version + b))
    