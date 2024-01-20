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

def get_version(address):
    version, _ = b58decode_check(address)
    #invalid version check
    if version not in [0, 111, 196]:
        raise ValueError('Invalid version')
    #mainnet version check
    if version in (MAIN_PUBKEY_HASH, MAIN_SCRIPT_HASH):
        return 'main'
    #testnet version check
    if version in (TEST_PUBKEY_HASH, TEST_SCRIPT_HASH):
        return 'test'

def bytes_to_wif(private_key, compressed=True, version=0):
    if compressed:
        private_key = private_key + b'\x01'
    return b58encode_check(private_key, version=version)

def wif_to_bytes(wif):
    return b58decode_check(wif) 

#address generation (public key to address) using ripemd160(sha256(public_key))
def public_key_to_address(public_key, version=0):
    return b58encode_check(ripemd160_sha256(public_key), version=version)

#public key generation using private key
def private_key_to_public_key(private_key, compressed=True):
    return ECPrivateKey(private_key).public_key.format(compressed=compressed)

#segwit address generation check spec BIP173
def public_key_to_segwit_address(public_key, version=0):
    #NOTE: b'\x00\x14' is the segwit scriptPubKey
    return bech32_encode(version, ripemd160_sha256(b'\x00\x14' + ripemd160_sha256(public_key)))

#redeemscript generation for multisig address
def multisig_to_redeemscript(public_key, m):
    #check redeemscript length 
    return b'\x50' + int_to_unknown_bytes(m) + b''.join([int_to_unknown_bytes(len(x)) + x for x in public_key]) + b'\x50' + b'\xae'

#multisig to address reverse of redeemscript generation
def multisig_to_address(public_key, m, version=0):
    return b58encode_check(ripemd160_sha256(sha256(multisig_to_redeemscript(public_key, m))), version=version)

