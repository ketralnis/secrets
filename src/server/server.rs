use std::path::Path;
use std::io::Write;
use std::io::Read;
use std::io::Cursor;

use rusqlite;
use rusqlite::types::ToSql;
use rusqlite::types::FromSql;
use sodiumoxide::crypto::box_;
use openssl::ssl::error::SslError;
use openssl::crypto::hash::Type as HashType;

use keys;
use utils;
use common::SecretsError;
use common::SecretsContainer;
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

        let mut db = try!(common::create_db(config_file));
        try!(create_server_schema(&mut db));
        let mut server = SecretsServer {db: db, password: password};
        server.create_and_store_keys(&cn);

        Ok(server)
    }

    pub fn connect<P: AsRef<Path>>(config_file: P,
                                   password: String)
                                   -> Result<Self, SecretsError> {
        let db = try!(common::connect_db(config_file));
        let instance = SecretsServer {db: db, password: password};
        return Ok(instance);
    }
}

impl SecretsContainer for SecretsServer {
    fn get_db(&mut self) -> &mut rusqlite::Connection {
        return &mut self.db;
    }

    fn get_password(&self) -> &String {
        return &self.password;
    }
}

fn create_server_schema(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    try!(conn.execute_batch("
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
    }
}
