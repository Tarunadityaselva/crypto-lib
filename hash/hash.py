import hashlib

#simple hashing function operate of string to compute 32-byte identifier
def id(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest(

#compute message digest of data and length ethereum style
def digest(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    message_length = len(data)
    hashed_messafe = sha256(f"{message_length}".encode('utf-8') + message)
    return hashed_message.hexdigest()

#return address of private key produced the signature
def verify_message(message, signature):
    digest = sha256(message)
    return recover_public_key(digest, signature)

