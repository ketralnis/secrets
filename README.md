Secrets is a system for safely storing shared passwords between users

# Features

1. Trustless. You don't have to trust the server. Users only need to trust each other
2. End to end encryption. The server never sees the passwords in plaintext
3. Revocability.
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

* CN checking/key pinning for the server
* user key caching/pinning
