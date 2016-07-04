features:
* it's currently impossible to change a store password. probably need an intermediate password store instead of individually encrypting things with it

useability:
  * user exists/service exists/grant exists messages should be better than sql errors

security:
* any security sensitive values including public keys should be signed, so attackers can't just insert their public keys right into the DB
* see: https://www.cs.ox.ac.uk/files/6487/pwvault.pdf
  - auth codes so people can't just modify our database (both on client and server)
  - merkle tree logs, maybe built out of those auth codes

documentation
* user level
* crypto level
