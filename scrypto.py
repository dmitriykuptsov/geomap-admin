# -*- coding: utf-8 -*-

from hashlib import sha256
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES
from os import urandom
from base64 import b64encode

KEY_SIZE = AES.block_size * 2
BLOCK_SIZE = AES.block_size
IV_SIZE = BLOCK_SIZE

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class AESCipher:
	def __init__(self, key):
		self.key = key;

	def encrypt(self, plaintext):
		padded_plaintext = pad(plaintext);
		iv = Random.new().read(BLOCK_SIZE);
		cipher = AES.new(self.key, AES.MODE_CBC, iv);
		return b64encode(iv + cipher.encrypt(padded_plaintext));

	def decrypt(self, ciphertext):
		ciphertext = b64decode(ciphertext);
		iv = ciphertext[:IV_SIZE];
		cipher = AES.new(self.key, AES.MODE_CBC, iv);
		return unpad(cipher.decrypt(ciphertext[IV_SIZE:])).decode('utf8');

class SRandom():
	@staticmethod
	def random_string(nbytes):
		random_bytes = urandom(nbytes);
		return b64encode(random_bytes);
