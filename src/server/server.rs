use std::path::Path;
use std::io;
use std::io::Write;

use rusqlite;
use rusqlite::Error as RusqliteError;
use rustc_serialize::base64::FromBase64;
use serde_json::Value as JsonValue;
use serde_json::from_slice as json_from_slice;

use utils;
use common::SecretsError;
use common::SecretsContainer;
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
        try!(server.create_and_store_keys(&cn));

        Ok(server)
    }

    pub fn connect<P: AsRef<Path>>(config_file: P,
                                   password: String)
                                   -> Result<Self, SecretsError> {
        let db = try!(common::connect_db(config_file));
        let instance = SecretsServer {db: db, password: password};
        return Ok(instance);
    }

    /// (called interactively)
    pub fn accept_join(&mut self, payload: &[u8]) -> Result<User, SecretsError> {
        let json_str = match payload.from_base64() {
            Err(_) => {
                return Err(SecretsError::Authentication("bad base64"));
            },
            Ok(json_str) => json_str
        };
        let got_json: JsonValue = try!(json_from_slice(&json_str));

        let attested_server_fingerprint = try!(common::json_get_string(&got_json, "server_fingerprint"));
        if attested_server_fingerprint != try!(self.ssl_fingerprint()) {
            return Err(SecretsError::Authentication("wrong server_fingerprint"));
        }

        let attested_server_cn = try!(common::json_get_string(&got_json, "server_cn"));
        if attested_server_cn != try!(self.ssl_cn()) {
            return Err(SecretsError::Authentication("wrong server_cn"));
        }

        let attested_server_public_key = try!(common::json_get_string(&got_json, "server_public_key"));
        let (public_key, _) = try!(self.get_keys());
        if attested_server_public_key != utils::hex(public_key.as_ref()) {
            return Err(SecretsError::Authentication("wrong server_public_key"));
        }

        let attested_server_public_sign = try!(common::json_get_string(&got_json, "server_public_sign"));
        let (public_sign, _) = try!(self.get_signs());
        if attested_server_public_sign != utils::hex(public_sign.as_ref()) {
            return Err(SecretsError::Authentication("wrong server_public_sign"));
        }

        let client_username = try!(common::json_get_string(&got_json, "client_username"));
        let client_fingerprint = try!(common::json_get_string(&got_json, "client_fingerprint"));
        let client_public_key = try!(common::json_get_string(&got_json, "client_public_key"));
        let client_public_sign = try!(common::json_get_string(&got_json, "client_public_sign"));

        if try!(self.user_exists(&client_username)) {
            return Err(SecretsError::Authentication("user exists"));
        }

        try!(io::stderr().write(format!("\
            client_username: {}\n\
            client_fingerprint: {}\n\
            client_public_key: {}\n\
            client_public_sign: {}\n\
            ",
            client_username, client_fingerprint,
            client_public_key, client_public_sign
        ).as_bytes()));
        let accepted = try!(utils::prompt_yn("does that look right? [y/n] "));
        if !accepted {
            return Err(SecretsError::Authentication("refused client authenticator"));
        }

        let user = try!(self.create_user(client_username, client_fingerprint,
                                         client_public_key, client_public_sign));
        info!("created user: {}", user.username);
        return Ok(user);
    }

    fn create_user(&self, username: String, fingerprint: String, public_key: String, public_sign: String) -> Result<User, SecretsError> {
        let db = self.get_db();
        try!(db.execute("
                INSERT INTO users(username, ssl_fingerprint, public_key, public_sign)
                VALUES(?,?,?,?)
            ",
            &[&username, &fingerprint, &public_key, &public_sign]));
        let user = try!(self.authenticate(username, fingerprint));
        return Ok(user);
    }

    fn user_exists(&self, username: &String) -> Result<bool, SecretsError> {
        let ret = self.get_db().query_row(
            "SELECT username FROM users WHERE username=?",
            &[username],
            |_row| { true });
        match ret {
            Ok(true) => Ok(true),
            Ok(_) => Err(SecretsError::Unknown("whastis?")),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(false),
            Err(err) => Err(SecretsError::Sqlite(err)),
        }
    }

    pub fn authenticate(&self, username: String, ssl_fingerprint: String) -> Result<User, SecretsError> {
        let db = self.get_db();
        let row = db.query_row("
            SELECT username
            FROM users
            WHERE username = ?
            AND ssl_fingerprint = ?
        ", &[&username, &ssl_fingerprint],
        |row| {
            User {username: row.get(0)}
        });
        let user = try!(row.map_err(|err| {
            match err {
                RusqliteError::QueryReturnedNoRows => SecretsError::Authentication("no match"),
                _ => SecretsError::Sqlite(err)
            }
        }));
        return Ok(user);
    }
}

impl SecretsContainer for SecretsServer {
    fn get_db(&self) -> &rusqlite::Connection {
        return &self.db;
    }

    fn get_password(&self) -> &String {
        return &self.password;
    }
}

pub struct User {
    username: String,
}

fn create_server_schema(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    try!(conn.execute_batch("
        CREATE TABLE users (
            username PRIMARY KEY NOT NULL,
            created INTEGER DEFAULT (CAST(STRFTIME('%s','now') AS INT)),
            modified INTEGER DEFAULT (CAST(STRFTIME('%s','now') AS INT)),
            public_key NOT NULL,
            public_sign NOT NULL,
            ssl_fingerprint NOT NULL,
            disabled INTEGER NULL DEFAULT NULL,
            auth_tag NOT NULL
        );
        CREATE TABLE services (
            service_name PRIMARY KEY NOT NULL,
            created INTEGER DEFAULT (CAST(STRFTIME('%s','now') AS INT)),
            modified INTEGER DEFAULT (CAST(STRFTIME('%s','now') AS INT)),
            creator REFERENCES users(username),
            last_set_by REFERENCES users(username),
            auth_tag NOT NULL
        );
        CREATE TABLE authorizations (
            username REFERENCES users(username),
            service_name REFERENCES services(service_name),
            created INTEGER DEFAULT (CAST(STRFTIME('%s','now') AS INT)),
            modified INTEGER DEFAULT (CAST(STRFTIME('%s','now') AS INT)),
            grantor REFERENCES users(username), -- who initially gave them permission
            last_set_by REFERENCES users(username),
            ciphertext, -- encrypted to username's public key
            auth_tag NOT NULL,
            PRIMARY KEY(username, service_name)
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
        let server = SecretsServer::connect(tempfile, password.to_string()).unwrap();
    }
}
