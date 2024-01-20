from web3 import Web3,Account

def get_create_address(tx):
    from_address = web3.toChecksumAddress(tx['from'])
    nonce = int(tx['nonce'])

    # Create a new account
    nonce_hex = hex(nonce)[2:]
    if nonce_hex == "0":
        nonce_hex = "0x"

    elif len(nonce_hex) % 2 != 0:
        nonce_hex = "0x0" + nonce_hex
    
    else:
        nonce_hex = "0x" + nonce_hex


    rlp_encoded = Web3.soliditySha3(["address", "bytes"], [from_address, nonce_hex])
    return Web3.toChecksumAddress("0x" + rlp_encoded.hex()[24:])

def get_create_address2(from_address, salt, init_code):
    # Create a new account
    rlp_encoded = Web3.soliditySha3(["address", "uint256", "bytes"], [from_address, salt, init_code])
    return Web3.toChecksumAddress("0x" + rlp_encoded.hex()[24:])

    