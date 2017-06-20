/// Code shared by `SecretsClient` and `SecretsServer`

use std::io;
use std::io::Cursor;
use std::path::Path;

use chrono::UTC;
use hyper;
use openssl::crypto::hash::Type as HashType;
use openssl::crypto::pkey::PKey;
use openssl::nid::Nid;
use openssl::ssl::error::SslError;
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::ssl::{SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3, SSL_OP_NO_COMPRESSION};
use openssl::x509::extension::Extension::KeyUsage;
use openssl::x509::extension::KeyUsageOption::DigitalSignature;
use openssl::x509::X509;
use openssl::x509::X509Generator;
use rfc1751::ToRfc1751Error;
use rusqlite::types::FromSql;
use rusqlite::types::ToSql;
use rusqlite;
use rustc_serialize::hex::{ToHex, FromHexError};
use serde_json::Error as SerdeError;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use url::ParseError;

use keys;
use keys::Authable;

quick_error! {
    #[derive(Debug)]
    pub enum SecretsError {
        Authentication(err: &'static str) {}
        ClientError(err: String) {} // client didn't like something the server did
        Crypto(err: keys::CryptoError) {from()}
        FromHex(err: FromHexError) {from()}
        HyperError(err: hyper::Error) {from()}
        Io(err: io::Error) {from()}
        Json(err: SerdeError) {from()}
        Parse(err: ParseError) {from()}
        ServerError(err: String) {} // server didn't like something the client did
        ServiceAlreadyExists(err: String) {}
        Sqlite(err: rusqlite::Error) {from()}
        Ssl(err: SslError) {from()}
        ToRfc1751(err: ToRfc1751Error) {from()}
        Unknown(err: &'static str) {}
        UserDoesntExist(err: String) {}
    }
}

pub fn init_ssl_cert(cn: &str) -> Result<(Vec<u8>, Vec<u8>), SecretsError> {
    let gen = X509Generator::new()
        .set_bitlength(4096)
        .add_name("CN".to_owned(), cn.to_string())
        .set_sign_hash(HashType::SHA256)
        .add_extension(KeyUsage(vec![DigitalSignature])); // so that we can sign client certs
    let (public_pem, private_pem) = gen.generate()?;

    let mut public_pem_vec = vec![];
    public_pem.write_pem(&mut public_pem_vec)?;

    let mut private_pem_vec = vec![];
    private_pem.write_pem(&mut private_pem_vec)?;

    Ok((public_pem_vec, private_pem_vec))
}

pub fn create_db<P: AsRef<Path>>(
    config_file: P,
) -> Result<rusqlite::Connection, SecretsError> {
    let conn = _connect_db(config_file, true)?;
    Ok(conn)
}

pub fn connect_db<P: AsRef<Path>>(
    config_file: P,
) -> Result<rusqlite::Connection, SecretsError> {
    let conn = _connect_db(config_file, false)?;
    check_db(&conn)?;
    Ok(conn)
}

fn _connect_db<P: AsRef<Path>>(
    path: P,
    create: bool,
) -> Result<rusqlite::Connection, rusqlite::Error> {
    let flags = if create {
        rusqlite::SQLITE_OPEN_READ_WRITE | rusqlite::SQLITE_OPEN_CREATE
    } else {
        rusqlite::SQLITE_OPEN_READ_WRITE
    };
    let mut conn = rusqlite::Connection::open_with_flags(path, flags)?;
    pragmas(&mut conn)?;
    if create {
        create_common_schema(&mut conn)?;
    }
    Ok(conn)
}

pub fn check_db(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    // just do a query that is expected to succeed, so server health checks
    // can be helpful
    conn.query_row("SELECT key from globals LIMIT 1", &[], |_| ())
}

fn pragmas(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    // sqlite config that must be done on every connection
    conn.execute_batch(
        "PRAGMA foreign_keys=ON;
         PRAGMA journal_mode=DELETE;
         PRAGMA secure_delete=true;

          -- this is a (probably misguided) attempt to keep password data off of
          -- disk at the expense of potentially crashing with OOM
         PRAGMA temp_store=MEMORY;
        ",
    )
}

fn create_common_schema(
    conn: &mut rusqlite::Connection,
) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE globals (
             key PRIMARY KEY NOT NULL,
             value NOT NULL,
             encrypted BOOL NOT NULL,
             modified INT NOT NULL
        );",
    )
}

pub fn default_ssl_context() -> Result<SslContext, SecretsError> {
    let mut ssl_context = SslContext::new(SslMethod::Tlsv1)?;
    ssl_context
        .set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);
    try!(
        ssl_context.set_cipher_list(
            "ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4@STRENGTH",
        )
    );
    Ok(ssl_context)
}

pub trait SecretsContainer {
    fn get_db(&self) -> &rusqlite::Connection;
    fn get_password(&self) -> &str;

    fn check_db(&self) -> Result<(), SecretsError> {
        let db = self.get_db();
        check_db(db)?;
        Ok(())
    }

    fn create_and_store_keys(&mut self, cn: &str) -> Result<(), SecretsError> {
        let (public_key, private_key) = box_::gen_keypair();
        self.set_global("public_key", &public_key.as_ref())?;
        self.set_encrypted_global("private_key", &private_key[..])?;

        let (public_sign, private_sign) = sign::gen_keypair();
        self.set_global("public_sign", &public_sign.as_ref())?;
        self.set_encrypted_global("private_sign", &private_sign[..])?;

        let (public_pem_vec, private_pem_vec) = init_ssl_cert(cn)?;
        self.set_global("public_pem", &public_pem_vec)?;
        self.set_encrypted_global("private_pem", &private_pem_vec)?;

        Ok(())
    }

    fn get_keys(
        &self,
    ) -> Result<(box_::PublicKey, box_::SecretKey), SecretsError> {
        let public_key_vec: Vec<u8> = self.get_global("public_key")?;
        let public_key = box_::PublicKey::from_slice(&public_key_vec);
        let public_key = public_key.ok_or(keys::CryptoError::Unknown)?;

        let private_key_vec: Vec<u8> =
            self.get_encrypted_global("private_key")?;
        let private_key = box_::SecretKey::from_slice(&private_key_vec);
        let private_key = private_key.ok_or(keys::CryptoError::Unknown)?;

        Ok((public_key, private_key))
    }

    fn get_signs(
        &self,
    ) -> Result<(sign::PublicKey, sign::SecretKey), SecretsError> {
        let public_sign_vec: Vec<u8> = self.get_global("public_sign")?;
        let public_sign = sign::PublicKey::from_slice(&public_sign_vec);
        let public_sign = public_sign.ok_or(keys::CryptoError::Unknown)?;

        let private_sign_vec: Vec<u8> =
            self.get_encrypted_global("private_sign")?;
        let private_sign = sign::SecretKey::from_slice(&private_sign_vec);
        let private_sign = private_sign.ok_or(keys::CryptoError::Unknown)?;

        Ok((public_sign, private_sign))
    }

    fn get_pems(&self) -> Result<(X509, PKey), SecretsError> {
        let public_key_vec: Vec<u8> = self.get_global("public_pem")?;
        let mut public_key_vec = Cursor::new(public_key_vec);
        let public_pem = X509::from_pem(&mut public_key_vec)?;

        let private_pem_vec: Vec<u8> =
            self.get_encrypted_global("private_pem")?;
        let mut private_pem_vec = Cursor::new(private_pem_vec);
        let private_pem = PKey::private_key_from_pem(&mut private_pem_vec)?;

        Ok((public_pem, private_pem))
    }

    fn ssl_cn(&self) -> Result<String, SecretsError> {
        let (public_pem, _) = self.get_pems()?;
        let cn = public_pem.subject_name().text_by_nid(Nid::CN);
        let cn = cn.ok_or(SecretsError::Unknown("pem has no CN"))?;
        let cn = cn.to_owned();
        Ok(cn)
    }

    fn ssl_fingerprint(&self) -> Result<String, SecretsError> {
        let (public_key, _) = self.get_pems()?;
        let fingerprint = public_key.fingerprint(HashType::SHA256);
        let fingerprint = fingerprint.ok_or(SecretsError::Unknown(
            "stored cert has \
             no fingerprint",
        ))?;
        let fingerprint = fingerprint.to_hex();
        Ok(fingerprint)
    }

    fn get_global<T: FromSql + Authable>(
        &self,
        key_name: &str,
    ) -> Result<T, SecretsError> {
        let conn = self.get_db();
        let value: T = try!(conn.query_row(
            "SELECT value FROM globals WHERE key = ? AND NOT encrypted",
            &[&key_name],
            |row| row.get(0)));
        Ok(value)
    }

    fn set_global<'a, T: ToSql + Authable>(
        &mut self,
        key_name: &str,
        value: &'a T,
    ) -> Result<(), SecretsError> {
        let conn = self.get_db();
        conn.execute(
            "INSERT OR REPLACE INTO globals(key, value, modified, encrypted)
             VALUES(?, ?, ?, 0)",
            &[&key_name, value, &UTC::now().timestamp()]
        )?;
        Ok(())
    }

    fn get_encrypted_global(
        &self,
        key_name: &str,
    ) -> Result<Vec<u8>, SecretsError> {
        let ciphertext: Vec<u8> = {
            let conn = self.get_db();
            conn.query_row(
                "SELECT value FROM globals WHERE key = ? AND \
                 encrypted",
                &[&key_name],
                |row| row.get(0),
            )
        }?;
        let password = self.get_password();
        let plaintext =
            keys::decrypt_blob_with_password(&ciphertext, password.as_bytes())?;
        Ok(plaintext)
    }

    fn set_encrypted_global(
        &mut self,
        key_name: &str,
        plaintext: &[u8],
    ) -> Result<(), SecretsError> {
        let ciphertext = {
            let password = self.get_password();
            keys::encrypt_blob_with_password(plaintext, password.as_bytes())
        }?;

        let db = self.get_db();
        db.execute(
            "INSERT OR REPLACE INTO globals(key, value, modified, encrypted)
             VALUES(?, ?, ?, 1)",
            &[&key_name, &ciphertext, &UTC::now().timestamp()]
        )?;
        Ok(())
    }
}
