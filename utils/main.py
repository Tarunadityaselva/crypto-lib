import os
import uuid

def uuid_v4():
    random_bytes = os
    #set the version to 4(0100)
    random_bytes = bytes((random_bytes[0] & 0x0f) | 0x40) + random_bytes[1:]
    #set varient to 1(10)
    random_bytes = bytes((random_bytes[8] & 0x3f) | 0x80) + random_bytes[9:]

    return str(uuid.UUID(bytes=random_bytes)
#RLP encoding
def arrayify_integer(value):
    result = bytearray()
    while value:
        result.append(value & 0xff)
        value >>= 8
    return result

def encode(object):
    if isinstance(object, int):
        if object == 0:
            return b''
        else:
            return b'\x00' + arrayify_integer(object)
    elif isinstance(object, bytes):
        if len(object) == 1 and object[0] < 0x80:
            return object
        else:
            return b'\x80' + encode(len(object)) + object
    elif isinstance(object, list):
        payload = b''.join(encode(item) for item in object)
        return b'\xc0' + encode(len(payload)) + payload
    else:
        raise TypeError("Unsupported type: {0}".format(type(object)))

