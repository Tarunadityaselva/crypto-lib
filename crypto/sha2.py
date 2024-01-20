#generate the sha256, sha512 hash using hashlib
def sha256(message: Any) -> Any:
    sha256 = hashlib.new('sha256')
    sha256.update(message)
    return sha256.digest()

def sha512(message: Any) -> Any:
    sha512 = hashlib.new('sha512')
    sha512.update(message)
    return sha512.digest()