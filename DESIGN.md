This tries to describe secrets' use of cryptography in a way that makes auditing easier.

All crypto is done with either [libsodium](https://download.libsodium.org/doc/) via the Rust binding [sodiumoxide](https://github.com/dnaq/sodiumoxide) (the vast majority) or [openssl](https://www.openssl.org/) (which is used for HTTPS authentication between the client and server).

# Overarching design goals:

* Sharing secret data with a small-to-medium team should be easy and secure.
* The server should never see plaintext. Plaintext should never leave the client and the server shouldn't be able to decrypt anything
* The server should be trustless. Even a malicious server should never compromise secret data
* It should be possible to revoke secrets and rotate them regularly without having to hunt down everyone that might know it
* Compromise attempts should be loud and obvious
* Auditing should be easy

# How secrets tries to achieve its goals

The server is a store of users' public keys and opaque encrypted blobs. Secret data is encrypted from one user's public key to another user's private key.

Creating or rotating a service involves fetching each grantee's public keys, encrypting the secret to them, and uploading to the server only that encrypted data. Similarly, granting access to an existing service involves an existing grantee of that service.

Once a user has seen the password to an external service, they can't "unknow" it. So there is no way to simply remove a grant: you must rotate the password (actually change the password on the external service, and update the grants) while withholding the new value from that user. For this reason, disabling a user (`secrets-server fire`) won't succeed until the given user holds no grants which can only be achieved by rotating every password they know.

# `PeerInfo`

This is the basic building block. The server and every client has a `PeerInfo`. It is fully public to all users of the server. It has these properties:

* `cn`: the user's username (or the fqdn of the server). It's also the common name on their SSL certificate
* `fingerprint`: the SHA256 of their SSL certificate
* `public_key`: a libsodium [box](https://download.libsodium.org/libsodium/content/public-key_cryptography/authenticated_encryption.html) using the  `crypto_box_curve25519xsalsa20poly1305` cipher suite
* `public_sign`: a libsodium [sign](https://download.libsodium.org/libsodium/content/public-key_cryptography/public-key_signatures.html) key using the `ed25519` signature scheme

In addition, the server and every client store these private data:

* their SSL certificate and private key
* `private_key`: the private side of `public_key`
* `private_sign`: the private side of `public_sign`

These private data are encrypted locally to the server or client. They are encrypted using libsodium [secretbox](https://download.libsodium.org/libsodium/content/secret-key_cryptography/authenticated_encryption.html) using the `crypto_secretbox_xsalsa20poly1305` cipher suite and a different random nonce per value. The key is generated from the store password (the argument to `-p`) using libsodium [pwhash](https://download.libsodium.org/libsodium/content/password_hashing/) with the `crypto_pwhash_scryptsalsa208sha256` cipher suite and a different random salt per value.

# Grants

This is the storage of the actual secret values. A Grant has

* `grantee`: who holds it, and to whos private key will decrypt it
* `grantor`: who granted it to `grantee`, and whose public key encrypted it
* `service_name`: the service it represent
* `created`: the creation timestamp
* `ciphertext`: the encrypted data
* `signature`: a signature using the grantor's `public_sign` that includes all of the above values. (This is included because the encryption ciphersuite doesn't provide non-repudiation so we provide it separately)

When creating a service, adding a grant to a user, or rotating a service, the target's `PeerInfo` is fetched and their public key is used to encrypt the Grant to them.

# Client<->server communication

HTTPS is used between the client and server using openssl. Authentication is done using client certificates. To determine if a connected client should be authenticated, the server checks the client certificate's CN and SHA256 fingerprint against the user in the database

* Client<->server authentication (joining)

To make joining a server safe, secrets tries to make it safe by involving human checking of fingerprints on both the client and the server

In order for a client to authenticate to the server, the client must first join the server. `secrets join` makes the client create its `PeerInfo` data in its local database, connects, and show the user the server it connected to in a report that looks like this:

```
=== secrets.vm ===
common name: secrets.vm
fingerprint: b957e10c998faa9909cff3ba4ec35485d04708c3ecc7481fe14d7f07bc0229cd
public key:  c15e697e4807793ef8a9461a7b2c6cf2266d1ec1480a594e83b54e7b75e07702
public sign: f1db594eb55fe97657c57f2aa01afd1210a46d42d80d5552ac4d548162d4968e
mnemonic:    AM ROBE KIT OMEN BATE ICY TROY RON WHAT HIP OMIT SUP LID CLAY AVER LEAR CAVE REEL CAN PAM FAN LUND RIFT ACME
does that look right? [y/n]
```

(`mnemonic` is a [rfc1751](https://tools.ietf.org/html/rfc1751) human-readable display of a SHA256 of the other values)

If they confirm, they are given a base64 summary of their own and the server's `PeerInfo` data and instructed to send it to the admin of the server (which must be transmitted using a side channel like email). This data is not encrypted or signed (we haven't established any mutually trusted keys yet). When the server is given this summary via `secrets-server accept-join`, the server double-checks that the server the client thought they connected to is in fact itself, prompts the server admin to double-check the client values using the same report format as above. If they confirm, the user has joined the server and can authenticate to it.

# Glossary

* Service: an external service, such as a bank
* A secret value: the secret data to be stored, such as the username and password to the bank account
* Grant: an instance of a secret value, encrypted from one user to another
* Grantor: the user giving access
* Grantee: a user that holds a Grant to a Service
* Server: an instance of `secrets-server` running somewhere
* Client: an instance of `secrets` with an associated user
* Rotation: changing the secret value by e.g. changing the password on the external service and updating secrets with the new value. This can add or remove grantees in the process
