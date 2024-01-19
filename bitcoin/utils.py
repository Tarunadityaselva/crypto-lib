import decimal
from binascii import hexlify

from coincurve.ecdsa import der_to_cdata

def hex_to_bytes(hex):
    if len(hex) & 1:
        hexed = hex + '0'

    return bytes.fromhex(hexed)

def int_to_hex(integer):
    return hex(integer)[2:]

def hex_to_int(hex):
    return int(hex, 16)

def int_to_varint(integer):
    if integer < 0xfd:
        return int_to_hex(integer)
    elif integer <= 0xffff:
        return 'fd' + int_to_hex(integer)
    elif integer <= 0xffffffff:
        return 'fe' + int_to_hex(integer)
    else:
        return 'ff' + int_to_hex(integer)

def script_push(val):
    if val < 0x4c:
        return int_to_hex(val)
    elif val <= 0xff:
        return '4c' + int_to_hex(val)
    elif val <= 0xffff:
        return '4d' + int_to_hex(val)
    else:
        return '4e' + int_to_hex(val)

def get_signatures_from_script(script):
    signatures = []
    for i in range(len(script)):
        if script[i] == 0x30 and script[i + 1] != 0x44:
            signature = script[i + 1: i + 1 + script[i + 1]]
            signatures.append(signature)
    return signatures