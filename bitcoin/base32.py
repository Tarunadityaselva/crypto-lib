from bitcoin.constants import BECH32_VERSION_SET

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    #bech32 polymod
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= BECH32_VERSION_SET[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(s):    
    #bech32 hrp expand
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]


def bech32_create_checksum(hrp, data):
    #bech32 create checksum
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):  
    #bech32 encode
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def bech32_decode(bech):
    #validate bech32 string 
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if (pos < 1 or pos + 7 > len(bech) or len(bech) > 90):
        return (None, None)
    if (not all(x in CHARSET for x in bech[pos+1:])):
        return (None, None)
    return (bech[:pos], [CHARSET.find(x) for x in bech[pos+1:]])

    