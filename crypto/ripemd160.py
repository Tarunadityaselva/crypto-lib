import hashlib
from typing import Any, Union

#computong ripemd160 hash
def ripemd160(message: Any) -> Any:
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(message)
    return ripemd160.digest()

