"""
Secure Timestamped Property List
---------------------------------

@author: Michael Bironneau <michael.bironneau@openenergi.com>

A timestamped, encrypted property list intended for use as an authentication token that is stored client-side in an HTTP cookie. Uses PBKDF2 to derive key and pads plaintext with random data before encrypting with AES-256 (CBC mode). The first block of the plaintext contains the timestamp and some (or all) of the user-defined properties, so that if the IV is tampered with an error will be raised on decryption (the IV only affects the first block in CBC-mode). Tampering with the padding (end 16 or so bytes) will not raise an InvalidTokenException and the token can still be decypted by someone who knows the derived key, but this neither affects the integrity of the payload nor its confidentiality - at best it allows an adversary to determine how long the payload is and how many padding bytes there are. In the future  could consider signing the padding to prevent this information from being revealed if it deemed significant enough.

Typical usage::

	Token.set_secret_key('my_secret_key')
	#encrypt
	t = Token()
	t.set(['user name', '111.24.32.23'])
	cookie = t.encrypt()
	#decrypt
	token = Token(cookie)
	user_id, ip_address = token.properties
	timestamp = token.timestamp


..warn:: Access to Token._key is not synchronized so in multi-threaded use it is possible for calls to decrypt() to fail if Token._key is changed between the time it is called and the time it returns. In practice this should not pose a problem but it is worth bearing in mind for testing purposes.

..note:: The encrypted token is always at least 48 characters long (2 blocks + IV)
..note:: Throughout is around 80k decryptions per second and 60k encryptions per second on Windows 7, Intel Core i-5 @ 3.2Ghz.
..note:: Does not deal with key rotation. 
"""
from Crypto.Cipher import AES
from pbkdf2 import PBKDF2
from os import urandom
import time
import binascii

class InvalidTokenException(Exception):
	pass

class Token(object):
	"""Represents a timestamped Token (list of properties that can contain information like user id, IP address, etc.)."""

	def set_secret_key(new_key, salt=None):
		"""Set secret encryption key at module level.

		Uses urandom to derive the salt, unless the user provides one explicitly.
		"""
		if salt:
			Token._key = PBKDF2(new_key, salt).read(32) #256-bit key
		else:
			Token._key = PBKDF2(new_key, urandom(8)).read(32) #256-bit key


	def decrypt(ciphertext):
		"""
		Decrypt ciphertext and return list containing timestamp followed by token properties. 

		Raise InvalidTokenException if the token is deemed to be invalid or cannot be decrypted.
		Raise RuntimeError if Token key has not been specified at run time.
		"""
		bytestr = binascii.unhexlify(ciphertext)
		if len(bytestr) < 2*AES.block_size:
			raise InvalidTokenException('Token is expected to be at least 32 characters long')
		iv = bytestr[:AES.block_size]
		payload = bytestr[AES.block_size:]
		cipher = None
		try:
			cipher = AES.new(Token._key, AES.MODE_CBC, iv)
		except AttributeError:
			raise RuntimeError("The encryption key must be set via Token.set_secret_key().")
		except TypeError:
			raise RuntimeError("The encryption key must be set via Token.set_secret_key()")
		plaintext = cipher.decrypt(payload).decode('unicode_escape')
		if '|' not in plaintext:
			#This is the only character that we can guarantee is in the output - therefore raise if it is not present
			raise InvalidTokenException("Token was encrypted with incorrect key or got corrupted in transport.")
		parts = plaintext.split('|')
		try:
			parts[0] = int(parts[0])
		except ValueError:
			raise InvalidTokenException("Token had a corrupt timestamp and is deemed to be invalid")
		return parts[:-1] #Exclude random padding

	def _pad(payload):
		"""
		Pad payload with random data so that it is a multiple of AES block size
		Always make sure that we add at least one block.
		"""
		num_of_blocks = int(len(payload)/AES.block_size) + 1
		if num_of_blocks == 1:
			num_of_blocks = 2
		rand_data = urandom(num_of_blocks*AES.block_size - len(payload)) #This is more data than we need but who cares
		rand_data = binascii.hexlify(rand_data).decode('utf-8')[:num_of_blocks*AES.block_size - len(payload) - 1] #-1 to include separator
		return payload + '|' + rand_data

	def set(self, properties):
		"""Set token properties. Prepends current time as integer. Properties should be a list of strings."""
		self.timestamp = int(time.time())
		self.properties = '|'.join(properties)

	def encrypt(self):
		"""Return a string with encrypted token."""
		iv = urandom(AES.block_size) #For the IV
		payload = Token._pad(str(self.timestamp) + '|' + self.properties)
		try:
			cipher = AES.new(Token._key, AES.MODE_CBC, iv)
		except AttributeError:
			raise RuntimeError("The encryption key must be set via Token.set_secret_key().")
		except TypeError:
			raise RuntimeError("The encryption key must be set via Token.set_secret_key()")
		ciphertext = (iv + cipher.encrypt(payload))
		return binascii.hexlify(ciphertext).decode('utf-8')

	def __init__(self, ciphertext=None):
		"""Initialize a token given an optional ciphertext string"""
		self.timestamp = 0
		self.properties = []
		if ciphertext:
			self.properties = Token._decrypt_cookie(ciphertext)
			self.timestamp = self.properties[0]
			self.properties = self.properties[1:]