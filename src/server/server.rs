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
use openssl::x509::X509Generator;
use openssl::crypto::hash::Type;
use openssl::x509::extension::Extension::KeyUsage;
use openssl::x509::extension::KeyUsageOption::DigitalSignature;

use keys;

pub struct Server {
    db_conn: rusqlite::Connection,
    password: String,
}

impl Server {
    pub fn create<P: AsRef<Path>>(config_file: P,
                                  cn: String,
                                  password: String)
                                  -> Result<Self, ServerError> {
        let db_conn = try!(Self::_connect_db(config_file, true));
        let mut server = Server {db_conn: db_conn, password: password};

        let (public_key, private_key) = keys::create_key();
        try!(server.set_global("public_key", &public_key.as_ref()));
        let encrypted_private_key = try!(Self::_encrypted(&private_key[..], server.password.as_bytes()));
        try!(server.set_global("private_key", &encrypted_private_key));

        let (public_pem, private_pem) = try!(init_ssl_cert(&cn));
        let mut public_pem_vec = vec![];
        try!(public_pem.write_pem(&mut public_pem_vec));
        try!(server.set_global("public_pem", &public_pem_vec));
        let mut private_pem_vec = vec![];
        try!(private_pem.write_pem(&mut private_pem_vec));
        let private_pem_encrypted = try!(Self::_encrypted(&private_pem_vec[..], server.password.as_bytes()));
        try!(server.set_global("private_pem", &private_pem_encrypted));

        try!(server.set_global("common_name", &cn));

        Ok(server)
    }

    pub fn connect<P: AsRef<Path>>(config_file: P,
                                   password: String)
                                   -> Result<Self, ServerError> {
        let db_conn = try!(Self::_connect_db(config_file, false));
        Ok(Server {db_conn: db_conn, password: password})
    }

    fn _connect_db<P: AsRef<Path>>(path: P, create: bool) -> Result<rusqlite::Connection, rusqlite::Error> {
        let flags = if create {
            rusqlite::SQLITE_OPEN_READ_WRITE | rusqlite::SQLITE_OPEN_CREATE
        } else {
            rusqlite::SQLITE_OPEN_READ_WRITE
        };
        let mut conn = try!(rusqlite::Connection::open_with_flags(path, flags));
        try!(pragmas(&mut conn));
        if create {
            try!(create_schema(&mut conn));
        }
        Ok(conn)
    }

    pub fn check_db(&mut self) -> Result<(), rusqlite::Error> {
        // just do a query that is expected to succeed, so server health checks
        // can be helpful
        self.db_conn.query_row("select 1", &[], |_| ())
    }

    pub fn get_keys(&mut self) -> Result<(box_::PublicKey, box_::SecretKey), ServerError> {
        let public_key_vec: Vec<u8> = try!(self.get_global("public_key"));
        let public_key = box_::PublicKey::from_slice(&public_key_vec);
        let public_key = try!(public_key.ok_or(keys::CryptoError::Unknown));

        let private_key_encrypted: Vec<u8> = try!(self.get_global("private_key"));
        let private_key_vec = try!(self.decrypt(&private_key_encrypted));
        let private_key = box_::SecretKey::from_slice(&private_key_vec);
        let private_key = try!(private_key.ok_or(keys::CryptoError::Unknown));

        return Ok((public_key, private_key));
    }

    pub fn get_pems(&mut self) -> Result<(X509, PKey), ServerError> {
        let public_key_vec: Vec<u8> = try!(self.get_global("public_pem"));
        let mut public_key_vec = Cursor::new(public_key_vec);
        let public_pem = try!(X509::from_pem(&mut public_key_vec));

        let private_pem_encrypted: Vec<u8> = try!(self.get_global("private_pem"));
        let private_pem_vec = try!(self.decrypt(&private_pem_encrypted));
        let mut private_pem_vec = Cursor::new(private_pem_vec);
        let private_pem = try!(PKey::private_key_from_pem(&mut private_pem_vec));

        return Ok((public_pem, private_pem));
    }

    fn get_global<T: FromSql>(&mut self, key_name: &str) -> Result<T, rusqlite::Error> {
        self.db_conn.query_row("SELECT value FROM globals WHERE key = ?",
                               &[&key_name],
                               |row| {
                                   row.get(0)
                               })
    }

    fn set_global<T: ToSql>(&mut self, key_name: &str, value: &T) -> Result<(), rusqlite::Error> {
        try!(self.db_conn.execute("
                INSERT OR REPLACE INTO globals(key, value) VALUES(?, ?)
            ", &[&key_name, value]));
        Ok(())
    }

    fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, keys::CryptoError> {
        Self::_decrypt(blob, self.password.as_bytes())
    }

    fn _decrypt(blob: &[u8], password: &[u8]) -> Result<Vec<u8>, keys::CryptoError> {
        keys::decrypt_blob_with_password(blob, password)
    }

    fn _encrypted(data: &[u8], password: &[u8]) -> Result<Vec<u8>, keys::CryptoError> {
        keys::encrypt_blob_with_password(data, password)
    }

    fn encrypted(&self, data: &[u8]) -> Result<Vec<u8>, keys::CryptoError> {
        return Self::_encrypted(data, &self.password.as_bytes())
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ServerError {
        Sqlite(err: rusqlite::Error) {from()}
        Ssl(err: SslError) {from()}
        Crypto(err: keys::CryptoError) {from()}
    }
}


fn init_ssl_cert<'ctx>(cn: &str) -> Result<(X509<'ctx>, PKey), SslError> {
    let gen = X509Generator::new()
        .set_bitlength(4096)
        .set_valid_period(365*5) // TODO need a way to renew this then?
        .add_name("CN".to_owned(), cn.to_string())
        .set_sign_hash(Type::SHA256)
        .add_extension(KeyUsage(vec![DigitalSignature])); // so that we can sign client certs
    return gen.generate();
}

fn pragmas(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    // sqlite config that must be done on every connection
    conn.execute_batch("
        PRAGMA application_id=0x53435253; -- SCRS
        PRAGMA foreign_keys=ON;
        PRAGMA journal_mode=DELETE;
        PRAGMA secure_delete=true;

        -- this is a (probably misguided) attempt to keep password data off of
        -- disk at the expense of potentially crashing with OOM
        PRAGMA temp_store=MEMORY;
    ")
}

fn create_schema(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    try!(conn.execute_batch("
        CREATE TABLE globals (
            key PRIMARY KEY,
            value
        );
        CREATE TABLE users (
            user_name PRIMARY KEY,
            user_email,
            created INTEGER,
            modified INTEGER,
            public_key,
            disabled INTEGER NULL DEFAULT NULL
        );
        CREATE TABLE services (
            service_name PRIMARY KEY,
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

        let created = Server::create(&tempfile, password.to_string(), cn).unwrap();
        drop(created);

        let mut server = Server::connect(tempfile, password.to_string()).unwrap();
        server.check_db().unwrap();
    }
}
