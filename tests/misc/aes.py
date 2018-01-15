# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import base64
import hashlib
from Crypto import Random, Cipher


class AES(object):

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(Cipher.AES.block_size)
        cipher = Cipher.AES.new(self.key, Cipher.AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:Cipher.AES.block_size]
        cipher = Cipher.AES.new(self.key, Cipher.AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[Cipher.AES.block_size:]))

    def _pad(self, s):
        return s + ((self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)).encode()

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
