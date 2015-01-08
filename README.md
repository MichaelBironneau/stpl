# Secure Timestamped Property List #

Author: Michael Bironneau (<michael.bironneau@openenergi.com>)

License: MIT

*Latest version 0.15*

Alternative implementation of authentication tokens for use with Tornado web server. For long-living authentication schemes where we want the tokens to survive server restarts, the current implementation is inadequate. Here we create a reusable timestamped encrypted property list that can be used for such purposes, for example storing the UserId and Ip Address in a timestamped, encrypted cookie. Our design loosely follows that of Microsoft's .ASPXAUTH cookie.

Our implementation guarantees:

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

##Description##
A timestamped, encrypted property list intended for use as an authentication token that is stored client-side in an HTTP cookie. Uses PBKDF2 to derive key and pads plaintext using PKCS#7 method before encrypting with AES-256 (CBC mode). The IV + ciphertext are then signed using Python's native HMAC-MD5 implementation.

Typical usage:

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


**Warning** Access to the secret key is not synchronized so in multi-threaded use it is possible for calls to decrypt() to fail if set_secret_key() is called from another thread between the time it is called and the time it returns. In practice this should not pose a problem but it is worth bearing in mind for testing purposes.

**Note:** The encrypted token is always at least 96 characters long 2x(IV + 1 block + HMAC)

**Note:** Throughout is around 80k decryptions per second and 60k encryptions per second on Windows 7, Intel Core i-5 @ 3.2Ghz.

**Note:** Does not deal with key rotation.