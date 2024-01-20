import logging
from collections import namedtuple

from itertools import islice
from typing import List, Tuple, Dict, Optional, Union, Iterable, Any
import math 
import re

import random import randint, shuffle

from bitcoin.crypto import double_sha256, sha256
from bitcoin.format import address_to_public_key_hash, public_key_to_address, public_key_to_coords, public_key_to_segwit_address, multisig_to_address, multisig_to_redeem_script, multisig_to_segwit_address, wif_to_bytes, bytes_to_wif, public_key_to_address, public_key_to_coords, public_key_to_segwit_address, multisig_to_address, multisig_to_redeem_script, multisig_to_segwit_address, wif_to_bytes, bytes_to_wif
from bitcoin.utils import (
    bytes_to_hex_string,
    encode_varint,
    hex_string_to_bytes,
    int_to_bytes,
    read_varint,
    sha256,
    varint_to_int,
)

from bitcoin.format import (verify_sig, get_version)
from bitcoin.base58 import (b58encode_check, b58decode_check)
from bitcoin.base32 import decode as segwit_decode

from bitcoin.constants import(
    TEST_SCRIPT_HASH,
    MAIN_SCRIPT_HASH,
    TEST_PRIVATE_KEY,
    MAIN_PRIVATE_KEY,
    TEST_PUBLIC_KEY,
    MAIN_PUBLIC_KEY,
    VERSION_BYTE_TO_ADDRESS_PREFIX,
    MARKER,
    OP_0,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSIG,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_PUSH_20,
    OP_RETURN,
    OP_EQUAL,
    MESSAGE_LIMIT,
)

class TxIn:
        __slots__ = ('script_sig', 'script_sig_len', 'txid', 'txindex', 'witness', 'amount', 'sequence', 'segwit_input')
        def __init__(self, txid: bytes, txindex: int, script_sig: bytes, amount: int, sequence: int = 0xffffffff, witness: List[bytes] = None):
            self.script_sig = script_sig
            self.script_sig_len = len(script_sig)
            self.txid = txid
            self.txindex = txindex
            self.witness = witness
            self.amount = amount
            self.sequence = sequence
            self.segwit_input = False

        def __repr__(self):
            return f"TxIn(txid={self.txid}, txindex={self.txindex}, script_sig={self.script_sig}, amount={self.amount}, sequence={self.sequence}, witness={self.witness})"

        def __eq__(self, other):
            return (
                self.script_sig == other.script_sig
                and self.txid == other.txid
                and self.txindex == other.txindex
                and self.witness == other.witness
                and self.amount == other.amount
                and self.sequence == other.sequence
            )

        def __hash__(self):
            return hash(
                (
                    self.script_sig,
                    self.txid,
                    self.txindex,
                    self.witness,
                    self.amount,
                    self.sequence,
                )
            )

        def is_segwit(self):
            return self.segwit_input

        Output = namedtuple("Output", "amount script_pubkey")


class TxOut:
    __slots__ = ('amount', 'script_pubkey', 'script_pubkey_len')

    def __init__(self, amount: int, script_pubkey: bytes):
        self.amount = amount
        self.script_pubkey = script_pubkey
        self.script_pubkey_len = len(script_pubkey)

    def __repr__(self):
        return f"TxOut(amount={self.amount}, script_pubkey={self.script_pubkey})"

    def __eq__(self, other):
        return (
            self.amount == other.amount
            and self.script_pubkey == other.script_pubkey
        )
    def __hash__(self):
        return hash((self.amount, self.script_pubkey))

    def __bytes__(self):
        return int_to_bytes(self.amount, 8) + encode_varint(self.script_pubkey_len) + self.script_pubkey

def TxObj:
    __slots__ = ('version', 'tx_ins', 'tx_outs', 'locktime', 'segwit')

    def __init__(self, version: int, tx_ins: List[TxIn], tx_outs: List[TxOut], locktime: int = 0, segwit: bool = False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.segwit = segwit    

    def __eq__(self, other):
        return (
            self.version == other.version
            and self.tx_ins == other.tx_ins
            and self.tx_outs == other.tx_outs
            and self.locktime == other.locktime
            and self.segwit == other.segwit
        )

    def __repr__(self):
        return f"TxObj(version={self.version}, tx_ins={self.tx_ins}, tx_outs={self.tx_outs}, locktime={self.locktime}, segwit={self.segwit})"


    def __bytes__(self):
        if self.segwit:
            return self.segwit_bytes()
        return self.non_segwit_bytes()

    def to_hex(self):
        return bytes_to_hex_string(bytes(self))

    def non_segwit_bytes(self):
        return (
            int_to_bytes(self.version, 4)
            + encode_varint(len(self.tx_ins))
            + b"".join(bytes(tx_in) for tx_in in self.tx_ins)
            + encode_varint(len(self.tx_outs))
            + b"".join(bytes(tx_out) for tx_out in self.tx_outs)
            + int_to_bytes(self.locktime, 4)
        )

    def segwit_bytes(self):
        return (
            int_to_bytes(self.version, 4)
            + MARKER
            + b"\x00"
            + encode_varint(len(self.tx_ins))
            + b"".join(bytes(tx_in) for tx_in in self.tx_ins)
            + encode_varint(len(self.tx_outs))
            + b"".join(bytes(tx_out) for tx_out in self.tx_outs)
        )

    def fee(self):
        return sum(tx_in.amount for tx_in in self.tx_ins) - sum(tx_out.amount for tx_out in self.tx_outs)


def parse_tx_obj(tx_obj: bytes) -> TxObj:
    tx_obj = io.BytesIO(tx_obj)
    version = varint_to_int(tx_obj.read(4))
    tx_ins = []
    tx_in_count = read_varint(tx_obj)
    for _ in range(tx_in_count):
        txid = tx_obj.read(32)[::-1]
        txindex = varint_to_int(tx_obj.read(4))
        script_sig_len = read_varint(tx_obj)
        script_sig = tx_obj.read(script_sig_len)
        sequence = varint_to_int(tx_obj.read(4))
        tx_ins.append(TxIn(txid, txindex, script_sig, sequence))
    tx_outs = []
    tx_out_count = read_varint(tx_obj)
    for _ in range(tx_out_count):
        amount = varint_to_int(tx_obj.read(8))
        script_pubkey_len = read_varint(tx_obj)
        script_pubkey = tx_obj.read(script_pubkey_len)
        tx_outs.append(TxOut(amount, script_pubkey))
    locktime = varint_to_int(tx_obj.read(4))
    return TxObj(version, tx_ins, tx_outs, locktime)

#transaction object deserialization
def deserialize(tx_obj: bytes) -> TxObj:
    if tx_obj[4] == 0:
        return parse_tx_obj(tx_obj)

    if segwit_decode(tx_obj[4:42])[0] == 0:
        return parse_tx_obj(tx_obj)

    if segwit_tx:
        for tx_in in segwit_tx.tx_ins:
            tx_in.segwit_input = True


#function to sign a transaction
def sign_input(tx_obj: TxObj, tx_in_index: int, private_key: ECPrivateKey, redeem_script: bytes = None) -> TxObj:
    tx_in = tx_obj.tx_ins[tx_in_index]
    if tx_in.segwit_input:
        return sign_segwit_input(tx_obj, tx_in_index, private_key, redeem_script)
    return sign_non_segwit_input(tx_obj, tx_in_index, private_key, redeem_script)

#function to sign a non-segwit transaction
def sign_non_segwit_input(tx_obj: TxObj, tx_in_index: int, private_key: ECPrivateKey, redeem_script: bytes = None) -> TxObj:
    tx_in = tx_obj.tx_ins[tx_in_index]
    tx_out = tx_obj.tx_outs[tx_in.txindex]
    if redeem_script is None:
        redeem_script = tx_out.script_pubkey
    sig = private_key.sign_input(tx_obj, tx_in_index, redeem_script)
    script_sig = (
        encode_varint(len(sig) + 1)
        + sig
        + encode_varint(len(private_key.public_key)) + private_key.public_key
    )
    tx_obj.tx_ins[tx_in_index] = TxIn(tx_in.txid, tx_in.txindex, script_sig, tx_out.amount)
    return tx_obj


