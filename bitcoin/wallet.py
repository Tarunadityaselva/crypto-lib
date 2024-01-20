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