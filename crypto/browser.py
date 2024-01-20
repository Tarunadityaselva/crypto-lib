import hashlib
import os

#choosing the hash algorithm
def create_hash(data):
    if data == 'sha256':
        return hashlib.sha256()
    elif data == 'sha512':
        return hashlib.sha512()
    else
        raise ValueError("Invalid hash algorithm")

def create_hmac(data, key, algorithm='sha256'):
    if algorithm == 'sha256':
        return hmac.new(key, data, hashlib.sha256)
    elif algorithm == 'sha512':
        return hmac.new(key, data, hashlib.sha512)
    else:
        raise ValueError("Invalid hash algorithm")

def pbkdf2`hmac(data, salt, iterations, key_length, algorithm='sha256'):
    if algorithm == 'sha256':
        return hashlib.pbkdf2_hmac('sha256', data, salt, iterations, key_length)
    elif algorithm == 'sha512':
        return hashlib.pbkdf2_hmac('sha512', data, salt, iterations, key_length)
    else:
        raise ValueError("Invalid hash algorithm")

def random_bytes(length):
    return os.urandom(length)