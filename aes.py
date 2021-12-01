import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import AES


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw.encode())
        iv = b'\xdeN\xafedf\xf1dX\x16r\x99\xa1\x04\x9d\xa0'
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        z=cipher.encrypt(raw)
        return base64.b64encode(iv + z)

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = b'\xdeN\xafedf\xf1dX\x16r\x99\xa1\x04\x9d\xa0'
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.decrypt(enc[AES.block_size:]).decode('utf-8')+"We are a family"

    def _pad(self, s):
        return s + ((self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)).encode()

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

