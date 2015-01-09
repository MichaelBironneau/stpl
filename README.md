# Secure Timestamped Property List #

Author: Michael Bironneau (<michael.bironneau@openenergi.com>)

License: MIT

*Latest version 0.17*

This repository hosts a signed, timestamped, encrypted property list that can be used for things like keeping track of the authenticated User Id and Ip Address in a web application. 

The implementation guarantees:

* Secrecy of property list (an attacker cannot see any of the stored properties without knowledge of the secret key)
* Message integrity (via HMAC-MD5)
* Compromise of either the HMAC key or encryption key does not compromise the other
* No vulnerability to timing attacks
* Suitable for long-lived authentication tokens that need to survive server restarts. In particular, the encryption/signature keys can be derived with predefined salts.
* All tokens are timestamped, so in particular it is possible to reject old tokens independently of client-side properties such as cookie expiration. 

##Installing##

    python setup.py install

Optionally, you may run the test suite:

    python setup.py test

##Implementation##
The user supplies a private key and two optional salts which we use to derive encryption and signing keys using PBKDF2. If no salt is provided two are generated using `urandom`. 


Next, the user supplies a list of property strings, `['a', 'b', 'c',...]` which is converted to a |-delimited string and to which `str(time.time())` is prepended.  This plaintext is padded using PKCS#7 method. An Initialization Vector (IV) is generated using `urandom` and the plaintext is then encrypted with AES-256 (CBC mode) using the key described above and the IV. 


The IV + ciphertext are then signed using Python's native HMAC-MD5 implementation with the signing key derived as described above, and this signature is appended to the message.

The decryption and verification process follow roughly the opposite process as above, with extra care taken in the verification step to use `compare_hash` method to prevent vulnerability due to timing attack.

##Typical usage:##

    from sectpl.token import Token
	Token.set_secret_keys('my_secret_key')
	#encrypt
	t = Token()
	t.set(['user name', '111.24.32.23'])
	cookie = t.encrypt()
	#decrypt
	token = Token(cookie)
	user_id, ip_address = token.properties
	timestamp = token.timestamp


For long-lived tokens, we can specify a salt explicitly and use the salt to manage a (possibly distributed) key rotation schedule:

    Token.set_secret_keys('my_secret_key', ['encryption_salt', 'hmac_salt'])

Instead of `token = Token(ciphertext)` we can also use `token = Token.decrypt(ciphertext)` - the two are equivalent.

**Warning** Access to the secret key is not synchronized so in multi-threaded use it is possible for calls to decrypt() to fail if set_secret_key() is called from another thread between the time it is called and the time it returns. In practice this should not pose a problem but it is worth bearing in mind for testing purposes.

**Note:** The encrypted token is always at least 96 characters long 2x(IV + 1 block + HMAC)

**Note:** Throughout is around 80k decryptions per second and 60k encryptions per second on Windows 7, Intel Core i-5 @ 3.2Ghz.

**Note:** Does not deal with key rotation.