import os

from Crypto.Cipher import AES


def seal(data):
    key = os.environ['DATA_KEY'].encode()
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt(data)
