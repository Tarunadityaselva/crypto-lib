from eth_account import eth_account
from eth_utils import keccak, to_checksum_address, to_bytes, big_endian_to_int
from eth_account._utils.legacy_transactions import encode_transaction, serializable_unsigned_transaction_from_dict  
from eth_account._utils.transactions import assert_valid_fields, Transaction
from eth_account.messages import encode_defunct
import rlp

#computing the ethereum address from the public key for transaction functionalities
def compute_address(key);
    #if key is private key compute, public key so as to compute the address
    if len(key) == 64 or (len(key) == 66 and key.startswith('0x')):
        acct = Account.from_key(key)
        pubkey = acct._key_obj.public_key
    else:
        #returning public key
        pubkey = key

    #removing the '0x04' prefix from the public key if present
    if pubkey.startswith(b'\x04'):
        pubkey = pubkey[4:]

    #compute the keccak hash of the public key
    address_bytes = keccak(bytes.fromhex(pubkey))[-20:]
    return '0x' + address_bytes.hex()

#recoving address from the signature
def recover_address(digest, signature):
    #recover the public key from the signature
    pubkey = Account.recover_message(encode_defunct(text=digest), signature=signature)
    return compute_address(pubkey)

#handling handling address
def handle_address(value):
    if value == '0x':
        return None
    return to_checksum_address(value)

def handle_number(value,param):
    if value == "0x":
        return 0

    return getNumber(value,param)

#handling unsigned integer for transaction
def handle_uint(value, params):
    if value == "0x":
        return 0

    value = getNumber(value, params)
    if value > BN_MAX_UINT:
        raise ValueError("Value exceeds uint256 range: %s" % value)
    return value

#handling formatting number
def format_number(value, name):
    value = getNumber(value, 'value')
    result = to_bytes(value)
    if len(result) > 32:
        raise ValueError("Value exceeds uint256 range: %s" % value)
    return result

#parse legacy
def parse_legacy(data):
    fields = rlp.decode(data, use_list = True)

    tx = {
        "type": 0,
        "nonce":handle_number(fields[0], "nonce"),
        "gasPrice": handle_number(fields[1], "gasPrice"),
        "gas": handle_number(fields[2], "gasLimit"),
        "to": handle_address(fields[3]),
        "value": handle_number(fields[4], "value"),
        "data": fields[5],
        "chainId": None,
    }

def serialize_legacy(tx, sig=None):
    fields = [
        format_number(tx["nonce"], "nonce"),
        format_number(tx["gasPrice"], "gasPrice"),
        format_number(tx["gas"], "gasLimit"),
        format_number(tx["to"] or b"", "to"),
        format_number(tx["value"], "value"),
        tx["data"],
    ]

    if not sig:
        if chain_id != 0:
            fields.append(format_number(chain_id, "chainId"))
            fields.append(b"")
            fields.append(b"")
        return rlp.encode(fields)


def _parse_eip_signature(tx, fields)
    try:
        y_parity = handle_number(fields[0],"yParity")
        if y_parity not in (0,1):
            raise ValueError("Invalid yParity value: %d" % y_parity)
    
    except KeyError:
        y_parity = None

    r = to_bytes(hexstr=fields[1]).rjust(32, b"\0")
    s = to_bytes(hexstr=fields[2]).rjust(32, b"\0")

    tx['signature'] = {'r': r, 's': s, 'v': y_parity}


class Transaction:
    def __init__(self, tx_data=None):
        self.tx = tx_data or {}

    #transaction hashing using keccak
    def hash(self):
        return web3.keccak(rlp.encode(self._encode_for_signing()))

    def from_address(self):
        return compute_address(self.sender_public_key())

    def from_public_key(self):
        if 'signature' not in self.tx_data or self.tx_data['signature'] is None:
            return None
        return Account.recoverHash(self.unsigned_hash, signature=self.tx_data['signature'])

    def is_signed(self):
        return 'signature' in self.tx_data and self.tx_data['signature'] is not None   

    def serialized (self):
        if not self.is_signed():
            raise ValueError("Cannot serialize unsigned transaction")

        type = self.infer.type()

        if type == 0:
            return _serialize_legacy(self.tx_data, self.tx_data['signature'])
        elif type == 1:
            return _serialize_eip2930(self.tx_data, self.tx_data['signature'])
        elif type == 2:
            return _serialize_eip1559(self.tx_data, self.tx_data['signature'])
        raise ValueError("Unsupported transaction type: %d" % type)

    def unsigned_serialized(self):
        type = self.infer_type()

        if type == 0:
            return serialize_legacy(self.tx_data)
        elif type == 1:
            return _serialize_eip2930(self.tx_data)
        elif type == 2:
            return _serialize_eip1559(self.tx_data)
        else:
            raise ValueError("Unsupported transaction type: %d" % type)