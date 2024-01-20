#computing the pbkdf2 using hashlib

import hashlib
from typing import Any, Union

def pbkdf2(password: Any, salt: Any, iterations: int=1000, keylen: int=16, algorithm: str='sha256') -> Any:
    #initialize the prf
    prf = hashlib.new(algorithm)
    #initialize the first block
    U = prf.copy()
    U.update(password + salt + b'\x00\x00\x00\x01')
    #initialize the output
    output = U.digest()
    #iterate
    for i in range(2, iterations + 1):
        #compute the next block
        U = prf.copy()
        U.update(password + salt + b'\x00\x00\x00' + bytes([i]))
        #xor it with the output
        output = bytes([x ^ y for x, y in zip(output, U.digest())])
    #return the result
    return output[:keylen]