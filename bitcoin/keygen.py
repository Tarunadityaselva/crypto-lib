import sys
import time
from multiprocessing import Event, Process, Queue, Value, cpu_count

from coincurve import Context

from bitcoin.base58 import b58encode_check,BASE58_ALPHABET
from bitcoin.crypto import ECPrivateKey, ripemd160_sha256
from bitcoin.format import bytes_to_wif, public_key_to_address

def generate_key_address_pair():
    context = Context()
    private_key = ECPrivateKey(context)
    public_key = private_key.public_key.format(compressed=False)
    address = public_key_to_address(public_key)
    return private_key, address

def generate_matching_address(address):
    private_key, generated_address = generate_key_address_pair()
    while generated_address != address:
        private_key, generated_address = generate_key_address_pair()
    return private_key

def generate_matching_address_multiprocess(address, stop_event, queue):
    while not stop_event.is_set():
        private_key = generate_matching_address(address)
        queue.put(private_key)
        
def generate_key_address_pairs(prefix, counter, match,queue):
    context = Context()

    while True:
        if match.is_set():
            break

        with counter.get_lock():
            counter.value += 1

        private_key = ECPrivateKey(context, prefix + counter.value.to_bytes(32, 'big'))
        address = b58encode_check(ripemd160_sha256(private_key.public_key.format(compressed=False)), version=0)