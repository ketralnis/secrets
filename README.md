Secrets is a system for safely storing shared passwords between users

# Features

1. Trustless. You don't have to trust the server. Users only need to trust each other.
2. End to end encryption. The server never sees the passwords in plaintext
3. Revocability. If everyone goes through Secrets, you have a good record of who knows what secrets. That means that your team can let someone go and know what password they have to rotate.
4. Rotation hygiene. Similar to revocability, you can easily rotate passwords without disrupting everyone

# Dependencies

* libsodium
* openssl
* a mess of rust libraries that cargo will handle for you

# Planned features

* 2fa support
  - totp to retrieve passwords
  - ability to forward totp for services without sharing the secret
* Optional master key that gets a copy of every password
* Web UI

# Unimplemented blockers

* user key caching/pinning
  - every time we see a user, cache the key we saw and error if it has changed
* it's currently impossible to change a store password. probably need an intermediate password store instead of individually encrypting things with it
* user exists/service exists/grant exists messages should be better than sql errors
* any security sensitive values including public keys should be signed, so attackers can't just insert their public keys right into the DB
* File format security. See: https://www.cs.ox.ac.uk/files/6487/pwvault.pdf
  - auth codes so people can't just modify our database (both on client and server)
  - merkle tree logs built out of those auth codes
* documentation
  - user level
  - crypto level
* validation of usernames, service names, etc

# Bugs

* Fix prompt to work like
[python's](https://svn.python.org/projects/python/tags/r32/Lib/getpass.py) or
ssh's (maybe try [termion](https://github.com/ticki/termion/blob/master/src/input.rs))
