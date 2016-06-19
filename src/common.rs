/// code shared by SecretsClient and SecretsServer

use std::path::Path;
use std::io;

use openssl::ssl::error::SslError;
use openssl::x509::X509Generator;
use openssl::x509::extension::KeyUsageOption::DigitalSignature;
use openssl::crypto::hash::Type as HashType;
use openssl::x509::extension::Extension::KeyUsage;
use rusqlite::types::ToSql;
use rusqlite::types::FromSql;
use hyper;
use rusqlite;

use utils;
use keys;

quick_error! {
    #[derive(Debug)]
    pub enum SecretsError {
        Sqlite(err: rusqlite::Error) {from()}
        Ssl(err: SslError) {from()}
        Crypto(err: keys::CryptoError) {from()}
        HyperError(err: hyper::Error) {from()}
        Io(err: io::Error) {from()}
        ServerError(err: String) {} // client had a problem communicating with server
        Unknown(err: &'static str) {}

        NotImplemented(err: &'static str) {}
    }
}

pub fn init_ssl_cert<'ctx>(cn: &str) -> Result<(Vec<u8>, Vec<u8>), SecretsError> {
    let gen = X509Generator::new()
        .set_bitlength(4096)
        .add_name("CN".to_owned(), cn.to_string())
        .set_sign_hash(HashType::SHA256)
        .add_extension(KeyUsage(vec![DigitalSignature])); // so that we can sign client certs
    let (public_pem, private_pem) = try!(gen.generate());

    let mut public_pem_vec = vec![];
    try!(public_pem.write_pem(&mut public_pem_vec));

    let mut private_pem_vec = vec![];
    try!(private_pem.write_pem(&mut private_pem_vec));

    return Ok((public_pem_vec, private_pem_vec));
}

pub fn create_db<P: AsRef<Path>>(config_file: P)
                                 -> Result<rusqlite::Connection, SecretsError> {
     let conn = try!(_connect_db(config_file, true));
     Ok(conn)
}

pub fn connect_db<P: AsRef<Path>>(config_file: P)
                                  -> Result<rusqlite::Connection, SecretsError> {
    let mut conn = try!(_connect_db(config_file, false));
    check_db(&mut conn);
    return Ok(conn);
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
        try!(create_common_schema(&mut conn));
    }
    Ok(conn)
}

pub fn check_db(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    // just do a query that is expected to succeed, so server health checks
    // can be helpful
    conn.query_row("SELECT 1", &[], |_| ())
}

fn pragmas(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    // sqlite config that must be done on every connection
    conn.execute_batch("
        PRAGMA foreign_keys=ON;
        PRAGMA journal_mode=DELETE;
        PRAGMA secure_delete=true;

        -- this is a (probably misguided) attempt to keep password data off of
        -- disk at the expense of potentially crashing with OOM
        PRAGMA temp_store=MEMORY;
    ")
}

fn create_common_schema(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch("
        CREATE TABLE globals (
            key PRIMARY KEY NOT NULL,
            value NOT NULL,
            encrypted BOOL NOT NULL
        );
    ")
}

pub fn get_global<T: FromSql>(conn: &mut rusqlite::Connection, key_name: &str) -> Result<T, rusqlite::Error> {
    conn.query_row(
        "SELECT value FROM globals WHERE key = ? AND NOT encrypted",
        &[&key_name],
        |row| { row.get(0) })
}

pub fn set_global<T: ToSql>(conn: &mut rusqlite::Connection, key_name: &str, value: &T) -> Result<(), rusqlite::Error> {
    try!(conn.execute(
        "INSERT OR REPLACE INTO globals(key, value, encrypted) VALUES(?, ?, 0)",
        &[&key_name, value]));
    Ok(())
}

pub fn get_encrypted_global(conn: &mut rusqlite::Connection,
                            key_name: &str,
                            password: &str)
                            -> Result<Vec<u8>, SecretsError> {
    let ciphertext: Vec<u8> = try!(
        conn.query_row(
            "SELECT value FROM globals WHERE key = ? AND encrypted",
            &[&key_name],
            |row| { row.get(0) }));
    let plaintext = try!(keys::decrypt_blob_with_password(&ciphertext,
                                                          password.as_bytes()));
    return Ok(plaintext);
}

pub fn set_encrypted_global(conn: &mut rusqlite::Connection,
                            password: &str,
                            key_name: &str,
                            plaintext: &[u8])
                            -> Result<(), SecretsError> {
    let ciphertext = try!(keys::encrypt_blob_with_password(&plaintext,
                                                           password.as_bytes()));
    try!(conn.execute(
        "INSERT OR REPLACE INTO globals(key, value, encrypted) VALUES(?, ?, 1)",
        &[&key_name, &ciphertext]));
    return Ok(())
}
