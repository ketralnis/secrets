use std::path::Path;
use std::io::Write;
use std::io::Read;
use std::io::Cursor;

use rusqlite;
use rusqlite::types::ToSql;
use rusqlite::types::FromSql;
use sodiumoxide::crypto::box_;
use openssl::ssl::error::SslError;
use openssl::x509::X509;
use openssl::crypto::pkey::PKey;
use openssl::crypto::hash::Type as HashType;

use keys;
use utils;
use common::SecretsError;
use common::init_ssl_cert;
use common;

pub struct SecretsServer {
    db: rusqlite::Connection,
    password: String,
}

impl SecretsServer {
    pub fn create<P: AsRef<Path>>(config_file: P,
                                  cn: String,
                                  password: String)
                                  -> Result<Self, SecretsError> {

        let db = try!(common::create_db(config_file));
        let mut server = SecretsServer {db: db, password: password};

        let (public_key, private_key) = keys::create_keypair();
        try!(server.set_global("public_key", public_key.as_ref()));
        try!(server.set_encrypted_global("private_key", &private_key[..]));

        let (public_pem_vec, private_pem_vec) = try!(init_ssl_cert(&cn));
        try!(server.set_global("public_pem", public_pem_vec));
        try!(server.set_encrypted_global("private_pem", &private_pem_vec));

        try!(server.set_global("common_name", cn));

        Ok(server)
    }

    pub fn connect<P: AsRef<Path>>(config_file: P,
                                   password: String)
                                   -> Result<Self, SecretsError> {
        let db = try!(common::connect_db(config_file));
        let mut instance = SecretsServer {db: db, password: password};
        return Ok(instance);
    }

    pub fn ssl_fingerprint(&mut self) -> Result<String, SecretsError> {
        let (public_key, _) = try!(self.get_pems());
        let fingerprint = public_key.fingerprint(HashType::SHA256);
        let fingerprint = try!(fingerprint.ok_or(SecretsError::Unknown("stored cert has no fingerprint")));
        let fingerprint = utils::hex(fingerprint);
        return Ok(fingerprint);
    }

    pub fn cn(&mut self) -> Result<String, SecretsError> {
        let cn = try!(self.get_global::<String>("common_name"));
        return Ok(cn);
    }

    pub fn get_keys(&mut self) -> Result<(box_::PublicKey, box_::SecretKey), SecretsError> {
        let public_key_vec: Vec<u8> = try!(self.get_global("public_key"));
        let public_key = box_::PublicKey::from_slice(&public_key_vec);
        let public_key = try!(public_key.ok_or(keys::CryptoError::Unknown));

        let private_key_vec: Vec<u8> = try!(self.get_encrypted_global("private_key"));
        let private_key = box_::SecretKey::from_slice(&private_key_vec);
        let private_key = try!(private_key.ok_or(keys::CryptoError::Unknown));

        return Ok((public_key, private_key));
    }

    pub fn get_pems(&mut self) -> Result<(X509, PKey), SecretsError> {
        let public_key_vec: Vec<u8> = try!(self.get_global("public_pem"));
        let mut public_key_vec = Cursor::new(public_key_vec);
        let public_pem = try!(X509::from_pem(&mut public_key_vec));

        let private_pem_vec: Vec<u8> = try!(self.get_encrypted_global("private_pem"));
        let mut private_pem_vec = Cursor::new(private_pem_vec);
        let private_pem = try!(PKey::private_key_from_pem(&mut private_pem_vec));

        return Ok((public_pem, private_pem));
    }

    fn get_global<T: FromSql>(&mut self, key_name: &str) -> Result<T, SecretsError> {
        let value = try!(common::get_global(&mut self.db, key_name));
        Ok(value)
    }

    fn set_global<T: ToSql>(&mut self, key_name: &str, value: T) -> Result<(), SecretsError> {
        try!(common::set_global(&mut self.db, key_name, &value));
        Ok(())
    }

    fn get_encrypted_global(&mut self, key_name: &str) -> Result<Vec<u8>, SecretsError> {
        let value = try!(common::get_encrypted_global(&mut self.db, key_name, &self.password));
        Ok(value)
    }

    fn set_encrypted_global(&mut self, key_name: &str, plaintext: &[u8]) -> Result<(), SecretsError> {
        try!(common::set_encrypted_global(&mut self.db, &self.password,
                                          key_name, plaintext));
        Ok(())
    }

    pub fn check_db(&mut self) -> Result<(), SecretsError> {
        try!(common::check_db(&mut self.db));
        Ok(())
    }
}

fn create_schema(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    try!(conn.execute_batch("
        CREATE TABLE globals (
            key PRIMARY KEY NOT NULL,
            value NOT NULL,
            encrypted BOOL NOT NULL
        );
        CREATE TABLE users (
            user_name PRIMARY KEY NOT NULL,
            user_email,
            created INTEGER,
            modified INTEGER,
            public_key,
            disabled INTEGER NULL DEFAULT NULL
        );
        CREATE TABLE services (
            service_name PRIMARY KEY NOT NULL,
            created INTEGER,
            modified INTEGER,
            creator REFERENCES users(user_name),
            last_set_by REFERENCES users(user_name)
        );
        CREATE TABLE authorizations (
            user_name REFERENCES users(user_name),
            service_name REFERENCES services(service_name),
            created INTEGER,
            modified INTEGER,
            grantor REFERENCES users(user_name), -- who initially gave them permission
            last_set_by REFERENCES users(user_name),
            ciphertext, -- encrypted to user_name's public key
            PRIMARY KEY(user_name, service_name)
        );
    "));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempdir;

    #[test]
    pub fn test_simple_create() {
        let dir = tempdir::TempDir::new("server.rs").unwrap();
        let password =  "hello".to_string();
        let cn = "me.local".to_string();
        let mut tempfile = dir.into_path();
        tempfile.push("server.db");

        debug!("Creating");
        let created = SecretsServer::create(&tempfile, password.to_string(), cn).unwrap();
        drop(created);

        debug!("Connecting");
        let mut server = SecretsServer::connect(tempfile, password.to_string()).unwrap();
        server.check_db().unwrap();
    }
}
