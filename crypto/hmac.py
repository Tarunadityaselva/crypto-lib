import hashlib
from typing import Any, Union

#computing the hmac of a message
def hmac(message: Any, key: Any, algorithm: str='sha256') -> Any:
    hmac = hashlib.new(algorithm, key)
    hmac.update(message)
    return hmac.digest()
