# README #

##Main use case##
Alternative implementation of authentication tokens for use with Tornado web server. For long-living authentication schemes where we want the tokens to survive server restarts, the current implementation is inadequate. Here we create a reusable timestamped encrypted property list that can be used for such purposes, for example storing the UserId and Ip Address in a timestamped, encrypted cookie. Our design loosely follows that of Microsoft's .ASPXAUTH cookie.

##Installing##

    python setup.py install

##Description##
A timestamped, encrypted property list intended for use as an authentication token that is stored client-side in an HTTP cookie. Uses PBKDF2 to derive key and pads plaintext with random data before encrypting with AES-256 (CBC mode). The first block of the plaintext contains the timestamp and some (or all) of the user-defined properties, so that if the IV is tampered with an error will be raised on decryption (the IV only affects the first block in CBC-mode). Tampering with the padding (end 16 or so bytes) will not raise an InvalidTokenException and the token can still be decypted by someone who knows the derived key, but this neither affects the integrity of the payload nor its confidentiality - at best it allows an adversary to determine how long the payload is and how many padding bytes there are. In the future  could consider signing the padding to prevent this information from being revealed if it deemed significant enough.

Typical usage:

    from sectpl.token import Token
	Token.set_secret_key('my_secret_key')
	#encrypt
	t = Token()
	t.set(['user name', '111.24.32.23'])
	cookie = t.encrypt()
	#decrypt
	token = Token(cookie)
	user_id, ip_address = token.properties
	timestamp = token.timestamp


**Warning** Access to Token._key is not synchronized so in multi-threaded use it is possible for calls to decrypt() to fail if Token._key is changed between the time it is called and the time it returns. In practice this should not pose a problem but it is worth bearing in mind for testing purposes.

**Note:** The encrypted token is always at least 48 characters long (2 blocks + IV)

**Note:** Throughout is around 80k decryptions per second and 60k encryptions per second on Windows 7, Intel Core i-5 @ 3.2Ghz.

**Note:** Does not deal with key rotation.