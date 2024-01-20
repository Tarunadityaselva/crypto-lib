from eth_utils import keccak, to_bytes, to_hex, to_checksum_address
import string

#getting the checksumaddress
def get_checksum_address(address):
    address = address.lower()
    hashed = keccak(text=address[2:])
    chars = list(address[2:])

    for i in range(0, 40, 2):
        if (hashed[i >> 1 ] >> 4) >= 8:
            chars[i] = chars[i].upper()
        if (hashed[i >> 1] & 0x0f) >= 8:
            chars[i + 1] = chars[i + 1].upper()

    return "0x" + "".join(chars)

#now checking the iban checksum
def iban_checksum(address):
    address = address.lower()
    address = address[4:] + address[:4]
    address = "".join([str(int(x, 16)) for x in address])
    address = int(address) % 97
    return address == 1

#base36 utilities
def from_base36(value):
    value = value.lower()
    result = 0
    for char in value:
        result *= 36
        if char.isdigit():
            result += int(char)
        else:
            result += ord(char) - 87
    return result

def get_address(address):
    if not isinstance(address, str):
        raise TypeError("Address must be a string")

    if address.startswith("0x") and len(address) == 42:
        return get_checksum_address(address)

    if address.startswith("XE") and len(address) == 44:
        if not iban_checksum(address):
            raise ValueError("IBAN checksum mismatch")
        address = address[4:]
        address = "".join([str(int(x, 16)) for x in address])
        address = "0x" + address[24:]
        return get_checksum_address(address)

def get_icap_address(address):
    hex_addr = get_address(address)[2:].lower() #remove 0x
    base36_addr = str(from_base36(hex_addr))
    return "XE" + iban_checksum("XE00" + base36_addr + "00") + base36_addr