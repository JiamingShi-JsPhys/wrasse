from Crypto.Cipher import AES, DES

KEY = b'8bytekey'
KEY16 = b'0123456789abcdef'


def encrypt(data):
    return DES.new(KEY).encrypt(data)


def seal(data):
    return AES.new(KEY16, AES.MODE_ECB)
