import json

from bitcoin.crypto import ECPrivateKey, ripemd160_sha256, sha256
from bitcoin.curve import Point
from bitcoin.format import (
    bytes_to_wif,
    public_key_to_address,
    public_key_to_coords,
    wif_to_bytes,
    multisig_to_address,
    multisig_to_redeem_script,
    public_key_to_segwit_address,
    multisig_to_segwit_address,
)

from bitcoin.utils import (hex_string_to_bytes, int_to_bytes, read_varint, sha256, varint_to_int)

from bitcoin.transaction import (
    calc_txid,
    TxIn,
    TxOut,
    Transaction,
    TxWitness,
    sign_tx,
    deserialize,
    address_to_public_key_hash
)

from bitcoin.constants import OP_0, OP_PUSH_20, OP_PUSH_32

from bitcoin.base58 import b58encode_check, b58decode_check
from bitcoin.base32 import decode as segwit_decode

def wif_to_key(wif: str) -> ECPrivateKey:
    """Convert a WIF private key to an ECPrivateKey object."""
    return ECPrivateKey.from_bytes(wif_to_bytes(wif))

def key_to_wif(key: ECPrivateKey, compressed: bool = True) -> str:
    """Convert an ECPrivateKey object to a WIF private key."""
    return bytes_to_wif(key.to_bytes(compressed=compressed))

class BaseKey:
    #elliptic curve key operation for bitcoin private key
    def __init__(self, key: ECPrivateKey, compressed: bool = True):
        self.key = key
        self.compressed = compressed

    def public_key(self) -> Point:
        """Return the public key."""
        return self.key.public_key

    def public_point(self) -> Point:
        """Return the public key."""
        return self.key.public_key

    def public_key_hash(self) -> bytes:
        """Return the public key hash."""
        return self.key.public_key_hash

    def address(self) -> str:
        """Return the address."""
        return public_key_to_address(self.public_key(), compressed=self.compressed)

    def public_point(self) -> Point:
        """Return the public key."""
        return self.key.public_key

    def public_key_hash(self) -> bytes:
        """Return the public key hash."""
        return self.key.public_key_hash

    def verify(self, signature: bytes, message: bytes) -> bool:
        """Verify a signature."""
        return self.key.verify(signature, message)

    def pub_to_hex(self) -> str:
        """Return the public key as a hex string."""
        return self.key.public_key.to_hex(compressed=self.compressed)

    def to_hex(self) -> str:
        """Return the private key as a hex string."""
        return self.key.to_hex()

    def to_bytes(self) -> bytes:
        """Return the private key as bytes."""
        return self.key.to_bytes()

    def to_wif(self) -> str:
        """Return the private key as a WIF string."""
        return key_to_wif(self.key, compressed=self.compressed)

    def to_der(self) -> bytes:
        """Return the private key as a DER string."""
        return self.key.to_der()

    def to_pem(self) -> str:
        """Return the private key as a PEM string."""
        return self.key.to_pem()

    def to_int(self) -> int:
        """Return the private key as an integer."""
        return self.key.to_int()

    def sign(self, message: bytes) -> bytes:
        """Sign a message."""
        return self.key.sign(message)

    def is_compressed(self):
        "return whether or not this private key is compressed"
        return True if len(self.key.public_key.to_bytes()) == 33 else False
    
    def __eq__(self, other):
        return self.to_int == other.to_int()

class PrivateKey(BaseKey):
    """
    bitcoin private key traits (NOTE:don't include this class in functions) 
    """
    def __init__(self, key: ECPrivateKey, compressed: bool = True):
        super().__init__(key, compressed=compressed)

    @classmethod
    def from_hex(cls, hex_string: str, compressed: bool = True) -> "PrivateKey":
        """Create a private key from a hex string."""
        return cls(ECPrivateKey.from_hex(hex_string), compressed=compressed)

    @classmethod
    def from_bytes(cls, byte_string: bytes, compressed: bool = True) -> "PrivateKey":
        """Create a private key from a byte string."""
        return cls(ECPrivateKey.from_bytes(byte_string), compressed=compressed)

    @classmethod
    def from_wif(cls, wif: str) -> "PrivateKey":
        """Create a private key from a WIF string."""
        return cls(wif_to_key(wif))

    @classmethod
    def from_der(cls, der: bytes) -> "PrivateKey":
        """Create a private key from a DER string."""
        return cls(ECPrivateKey.from_der(der))

    @classmethod
    def from_pem(cls, pem: str) -> "PrivateKey":
        """Create a private key from a PEM string."""
        return cls(ECPrivateKey.from_pem(pem))

    @classmethod
    def from_int(cls, num: int, compressed: bool = True) -> "PrivateKey":
        """Create a private key from an integer."""
        return cls(ECPrivateKey.from_int(num), compressed=compressed)

    @classmethod
    def generate(cls, compressed: bool = True) -> "PrivateKey":
        """Generate a random private key."""
        return cls(ECPrivateKey.generate(), compressed=compressed)

    def create_transaction(self, outputs, fee,leftover, combine, message, unspents):
        #P2PKH transaction signed transaction

        return_address = self.segwit_address if any([self.segwit_address, self.segwit_address]) else self.address
        #create transaction
        return create_transaction(self, outputs, fee, leftover, combine, message, unspents)

    def send(self, outputs, fee, leftover, combine, message, unspents):
        #P2PKH transaction signed transaction

        return_address = self.segwit_address if any([self.segwit_address, self.segwit_address]) else self.address
        #create transaction
        return send(self, outputs, fee, leftover, combine, message, unspents)

    def create_segwit_transaction(self, outputs, fee, leftover, combine, message, unspents):
        #P2WPKH transaction signed transaction

        return_address = self.segwit_address if any([self.segwit_address, self.segwit_address]) else self.address
        #create transaction
        return create_segwit_transaction(self, outputs, fee, leftover, combine, message, unspents)

    def prepare_transaction(cls, address, outputs, fee, leftover, combine, message, unspents):
        #P2PKH transaction unsigned transaction

        return_address = self.segwit_address if any([self.segwit_address, self.segwit_address]) else self.address
        #create transaction
        return prepare_transaction(self, address, outputs, fee, leftover, combine, message, unspents)



    #implementation of the signing transaction for signed P2PKH transaction
    def sign_transaction(self, transaction, unspents):
        #sign transaction
        data = json.loads(transaction)

        unsigned_tx = [Unspent.from_dict(unspent) for unspent in unspents]
        outputs = [TxOut.from_dict(output) for output in data["outputs"]]

        tx_data = deserialize(outputs)
        return sign_tx(tx_data, unsigned_tx, self)

    def from_hex(cls, hex_string: str, compressed: bool = True) -> "PrivateKey":
        """Create a private key from a hex string."""
        return cls(ECPrivateKey.from_hex(hex_string), compressed=compressed)

    def from_der(cls, der: bytes) -> "PrivateKey":
        """Create a private key from a DER string."""
        return cls(ECPrivateKey.from_der(der))

    def from_pem(cls, pem: str) -> "PrivateKey":
        """Create a private key from a PEM string."""
        return cls(ECPrivateKey.from_pem(pem))

    def from_int(cls, num: int, compressed: bool = True) -> "PrivateKey":
        """Create a private key from an integer."""
        return cls(ECPrivateKey.from_int(num), compressed=compressed)

    

class MultiSig:
    """
    multi signature traits, class represting the multisig wallet management,

    don't include this class in functions
    """

    def __init__(self, keys: list, m: int, n: int, compressed: bool = True):
        self.keys = keys
        self.m = m
        self.n = n
        self.compressed = compressed

    def public_key(self) -> Point:
        """Return the public key."""
        return self.key.public_key

    def public_point(self) -> Point:
        """Return the public key."""
        return self.key.public_key

    def public_key_hash(self) -> bytes:
        """Return the public key hash."""
        return self.key.public_key_hash

    def address(self) -> str:
        """Return the address."""
        return multisig_to_address(self.keys, self.m, self.n, compressed=self.compressed)

    def public_point(self) -> Point:
        """Return the public key."""
        return self.key.public_key

    def public_key_hash(self) -> bytes:
        """Return the public key hash."""
        return self.key.public_key_hash

    def verify(self, signature: bytes, message: bytes) -> bool:
        """Verify a signature."""
        return self.key.verify(signature, message)

    def pub_to_hex(self) -> str:
        """Return the public key as a hex string."""
        return self.key.public_key.to_hex(compressed=self.compressed)

    def to_hex(self) -> str:
        """Return the private key as a hex string."""
        return self.key.to_hex()

    def to_bytes(self) -> bytes:
        """Return the private key as bytes."""
        return self.key.to_bytes()

    def to_wif(self) -> str:
        """Return the private key as a WIF string."""
        return key_to_wif(self.key, compressed=self.compressed)

    def to_der(self) -> bytes:
        """Return the private key as a DER string."""
        return self.key.to_der()

    def to_pem(self) -> str:
        """Return the private key as a PEM string."""
        return self.key.to_pem()

    def to_int(self) -> int:
        """Return the private key as an integer."""
        return self.key.to_int()

    def sign(self, message: bytes) -> bytes:
        """Sign a message."""
        return self.key.sign(message)

    def is_compressed(self):
        "return whether or not this private key is compressed"
        return True if len(self.key.public_key.to_bytes()) == 33


    def get_balance(self):
        #get balance of multisig wallet
        return get_balance(self.address)

    def get_unspents(self):
        #get unspents of multisig wallet
        p2sh_size = 1 + self.m * 74 + len(self.keys) * 34 + 1 + 1
        #outpoint_size = 32 + 4 * p2sh_size 
        add_p2sh_vsize = 36 + p2sh_size * 4
        
        return get_unspents(self.address, p2sh_size)


    def create_transaction(self, outputs, fee, leftover, combine, message, unspents):
        #P2SH transaction signed transaction

        return_address = self.segwit_address if any([self.segwit_address, self.segwit_address]) else self.address
        #create transaction
        return create_transaction(self, outputs, fee, leftover, combine, message, unspents)

    def prepare_transaction(cls, address, outputs, fee, leftover, combine, message, unspents):
        #P2SH transaction unsigned transaction

        return_address = self.segwit_address if any([self.segwit_address, self.segwit_address]) else self.address
        #create transaction
        return prepare_transaction(self, address, outputs, fee, leftover, combine, message, unspents)

    def sign_transaction(self, transaction, unspents):
        #sign transaction
        data = json.loads(transaction)

        unsigned_tx = [Unspent.from_dict(unspent) for unspent in unspents]
        outputs = [TxOut.from_dict(output) for output in data["outputs"]]

        tx_data = deserialize(outputs)
        return sign_tx(tx_data, unsigned_tx, self)

        