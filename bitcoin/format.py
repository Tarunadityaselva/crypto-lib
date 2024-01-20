from coincurve import verify_signature

from bitcoin.base58 import b58encode_check, b58decode_check
from bitcoin.crypto import ripemd160_sha256, sha256 

from bitcoin.utils import int_to_unknown_bytes, unknown_bytes_to_int, hex_to_bytes
from bitcoin.base32 import bech32_decode

from bitcoin.constants import(
    BASE58_ALPHABET,
    BECH32_ALPHABET,
    BECH32_ALPHABET_R,
    BECH32_ALPHABET_MAP,
    BECH32_SEPARATOR,
    BECH32_SEPARATOR_POSITION,
    BECH32_CHECKSUM_LENGTH,
    BECH32_CHECKSUM_POSITION,
    BECH32_CHECKSUM_MASK,
    BECH32_CHECKSUM_GENERATOR,
    BECH32_CHECKSUM_GENERATOR_REV,
    BECH32_MINIMUM_LENGTH,
    BECH32_MAXIMUM_LENGTH,
    BECH32_MAXIMUM_DATA_LENGTH,
    BECH32_MINIMUM_DATA_LENGTH,
    BECH32_HRP_MINIMUM_LENGTH,
    BECH32_HRP_MAXIMUM_LENGTH,
    BECH32_HRP_ALLOWED_CHARSET,
    BECH32_HRP_ALLOWED_CHARSET_MAP,
    BECH32_HRP_INVALID_CHARSET,
    BECH32_HRP_INVALID_CHARSET_MAP,
    BECH32_HRP_SEPARATOR_POSITION
)

def verify_sig(message, signature, public_key):
    return verify_signature(signature, message, public_key)

