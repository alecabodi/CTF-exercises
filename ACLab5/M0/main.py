from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import HMAC, SHA256, MD5, SHA1


# Salt is 20 bytes
def onion(pw, salt, secret):
    h1 = MD5.new()
    h1.update(pw)
    h1 = h1.digest()
    h2 = HMAC.new(key=salt, msg=h1, digestmod=SHA1).digest()
    h3 = HMAC.new(key=secret, msg=h2, digestmod=SHA256).digest()

    # Use n = 2**10, r = 32, p = 2, key_len = 64
    h4 = scrypt(password=h3, salt=salt, N=2**10, r=32, p=2, key_len=64)
    h5 = HMAC.new(key=salt, msg=h4, digestmod=SHA256).hexdigest()
    return h5


PW = bytes.fromhex('6f6e696f6e732061726520736d656c6c79')
SECRET = bytes.fromhex('6275742061726520617765736f6d6520f09f988b')
SALT = bytes.fromhex('696e2061206e69636520736f6666726974746f21')

print(onion(PW, SALT, SECRET))
