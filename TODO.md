* it's currently impossible to change a store password. probably need an intermediate password store instead of individually encrypting things with it
* any security sensitive values including public keys should be signed, so attackers can't just insert their public keys right into the DB
* user exists/service exists/auth exists messages should be better than sql errors
* auth codes so people can't just modify our database (both on client and server)
* merkle tree logs, maybe built out of those auth codes
