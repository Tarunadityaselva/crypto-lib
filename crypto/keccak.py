#keccak crypto hash functions
import hashlib
from typing import Any, Union

#keccak hash function
def keccak(message: Any, algorithm: str='sha256') -> Any:
    keccak = hashlib.new(algorithm)
    keccak.update(message)
    return keccak.digest()

