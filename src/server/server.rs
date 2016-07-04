use std::path::Path;
use std::io;
use std::io::Write;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use rusqlite;
use rustc_serialize::base64::FromBase64;
use serde_json::Value as JsonValue;
use serde_json::from_slice as json_from_slice;
use time;

use keys;
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

        let client_public_key = try!(
            utils::unhex(&client_public_key)
            .and_then(|x| box_::PublicKey::from_slice(&x))
            .ok_or(keys::CryptoError::CantDecrypt));
        let client_public_sign = try!(
            utils::unhex(&client_public_sign)
            .and_then(|x| sign::PublicKey::from_slice(&x))
            .ok_or(keys::CryptoError::CantDecrypt));

        let user = try!(self.create_user(client_username, client_fingerprint,
                                         client_public_key, client_public_sign));
        info!("created user: {}", user.username);
        return Ok(user);
    }

    fn create_user(&self, username: String,
                   ssl_fingerprint: String,
                   public_key: box_::PublicKey,
                   public_sign: sign::PublicKey) -> Result<User, SecretsError> {
        let now = time::get_time().sec;
        try!(self.db.execute("
                INSERT INTO users(username, ssl_fingerprint,
                                  public_key, public_sign,
                                  created)
                VALUES(?,?,?,?,?)
            ",
            &[&username, &ssl_fingerprint,
              &public_key.as_ref(), &public_sign.as_ref(),
              &now]));
        let user = try!(self.get_user(&username));
        return Ok(user);
    }

    fn get_user(&self, username: &String) -> Result<User, SecretsError> {
        let user = try!(self.db.query_row_and_then("
                SELECT username, public_key, public_sign, ssl_fingerprint,
                       created, disabled
                FROM users
                WHERE username=?
            ",
            &[username],
            User::from_row));
        return Ok(user);
    }

    fn user_exists(&self, username: &String) -> Result<bool, SecretsError> {
        match self.get_user(username) {
            Ok(_) => Ok(true),
            Err(SecretsError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => Ok(false),
            Err(x) => Err(x)
        }
    }

    pub fn authenticate(&self, username: &String, ssl_fingerprint: &String) -> Result<User, SecretsError> {
        let user = match self.get_user(username) {
            Ok(user) => user,
            Err(SecretsError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                return Err(SecretsError::Authentication("no user"))
            },
            Err(x) => return Err(x),
        };
        if !utils::constant_time_compare(&user.ssl_fingerprint.as_bytes(),
                                         &ssl_fingerprint.as_bytes()) {
            return Err(SecretsError::Authentication("bad fingerprint match"))
        }
        if user.disabled.is_some() {
            return Err(SecretsError::Authentication("user is disabled"))
        }
        return Ok(user);
    }

    pub fn get_service(&self, service_name: &String) -> Result<Service, SecretsError> {
        let service = try!(self.db.query_row_and_then("
                SELECT service_name, created, modified, creator, last_set_by
                FROM services
                WHERE service_name=?
            ",
            &[service_name],
            Service::from_row));
        return Ok(service);
    }

    pub fn create_service(&mut self,
                          service_name: String,
                          user: &User,
                          ciphertext: Vec<u8>) -> Result<Service, SecretsError> {
        {
            let now = time::get_time().sec;
            let trans = try!(self.db.transaction());
            try!(trans.execute("
                    INSERT INTO services(service_name, created, modified,
                                         creator, last_set_by)
                    VALUES(?,?,?,?,?)
                ",
                &[&service_name, &now, &now, &user.username, &user.username]));
            // we create the automatic self-grant
            try!(trans.execute("
                    INSERT INTO grants(service_name, grantor, grantee, ciphertext,
                                       created)
                    VALUES (?,?,?,?,?)
                ",
                &[&service_name, &user.username, &user.username, &ciphertext,
                  &now]));
            try!(trans.commit());
        }
        let service = try!(self.get_service(&service_name));
        return Ok(service);
    }

    pub fn rotate_service(&mut self,
                          service_name: String,
                          grantor: &User,
                          grants: &[(&User, &Vec<u8>, &sign::Signature)])
                          -> Result<(), SecretsError> {
        // make sure the service exists
        let service = try!(self.get_service(&service_name));
        let now = time::get_time().sec;
        let trans = try!(self.db.transaction());
        try!(trans.execute_batch("
                CREATE TEMPORARY TABLE new_grants(grantee PRIMARY KEY)
            "));
        for &(ref grantee, ref ciphertext, ref signature) in grants {
            if grantee.disabled.is_some() {
                return Err(SecretsError::Authentication("can't grant to disabled user"));
            }
            // make sure the signature matches
            if !sign::verify_detached(&signature,
                                      ciphertext,
                                      &grantor.public_sign) {
                return Err(SecretsError::Crypto(keys::CryptoError::CantDecrypt));
            }
            try!(trans.execute("
                    INSERT INTO new_grants(grantee) VALUES(?)
                ", &[&grantee.username]));
            try!(trans.execute("
                    INSERT OR REPLACE INTO grants(grantor, grantee, service_name,
                                                  created, ciphertext, signature)
                    VALUES (?, ?, ?, ?, ?, ?)
                ", &[&grantor.username, &grantee.username, &service.service_name,
                     &now, *ciphertext, &signature.as_ref()]));
            try!(trans.execute("
                    UPDATE services SET modified=?, last_set_by=?
                ", &[&now, &grantor.username]));
            try!(trans.execute_batch("
                    DELETE FROM grants
                    WHERE grantee NOT IN (SELECT grantee FROM new_grants);
                "));
        }
        try!(trans.commit());
        return Ok(());
    }

    pub fn get_grant(&self,
                     service_name: String,
                     user: &User)
                     -> Result<Grant, SecretsError> {
        let grant = try!(self.db.query_row_and_then("
                SELECT service_name, grantee, grantor, ciphertext, signature, created
                FROM grants
                WHERE service_name = ? AND grantee = ?
             ",
            &[&service_name, &user.username],
            Grant::from_row));
        // verify the signature on the grant TODO these can be NULL if it was granted and taken away
        let grantor = try!(self.get_user(&grant.grantor));
        if !sign::verify_detached(&grant.signature,
                                  &grant.ciphertext,
                                  &grantor.public_sign) {
            return Err(SecretsError::Crypto(keys::CryptoError::CantDecrypt));
        }
        return Ok(grant);
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
    public_key: box_::PublicKey,
    public_sign: sign::PublicKey,
    ssl_fingerprint: String,
    created: i64,
    disabled: Option<i64>,
}

impl User {
    fn from_row(row: rusqlite::Row) -> Result<Self, SecretsError> {
        let public_key: Vec<u8> = row.get("public_key");
        let public_key = try!(box_::PublicKey::from_slice(&public_key.as_ref())
            .ok_or(keys::CryptoError::CantDecrypt));

        let public_sign: Vec<u8> = row.get("public_sign");
        let public_sign = try!(sign::PublicKey::from_slice(&public_sign.as_ref())
            .ok_or(keys::CryptoError::CantDecrypt));

        let u = User {
            username: row.get("username"),
            public_key: public_key,
            public_sign: public_sign,
            ssl_fingerprint: row.get("ssl_fingerprint"),
            created: row.get("created"),
            disabled: row.get("disabled"),
        };
        Ok(u)
    }
}

pub struct Service {
    service_name: String,
    created: i64,
    modified: i64,
    creator: String,
    last_set_by: String
}

impl Service {
    fn from_row(row: rusqlite::Row) -> Result<Self, SecretsError> {
        let s = Service {
            service_name: row.get("service_name"),
            created: row.get("created"),
            modified: row.get("modified"),
            creator: row.get("creator"),
            last_set_by: row.get("last_set_by"),
        };
        Ok(s)
    }
}

pub struct Grant {
    grantee: String,
    grantor: String,
    service_name: String,
    ciphertext: Vec<u8>,
    signature: sign::Signature,
    created: i64,
}

impl Grant {
    fn from_row(row: rusqlite::Row) -> Result<Self, SecretsError> {
        let sig: Vec<u8> = row.get("signature");
        let signature = try!(
            sign::Signature::from_slice(&sig)
            .ok_or(keys::CryptoError::CantDecrypt));

        let u = Grant {
            grantee: row.get("grantee"),
            grantor: row.get("grantor"),
            service_name: row.get("service_name"),
            ciphertext: row.get("ciphertext"),
            signature: signature,
            created: row.get("created"),
        };
        Ok(u)
    }
}

fn create_server_schema(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    try!(conn.execute_batch("
        CREATE TABLE users (
            username PRIMARY KEY NOT NULL,
            public_key NOT NULL,
            public_sign NOT NULL,
            ssl_fingerprint NOT NULL,
            created INTEGER NOT NULL,
            disabled INTEGER NULL DEFAULT NULL
        );

        CREATE TABLE services (
            service_name PRIMARY KEY NOT NULL,
            created INTEGER NOT NULL,
            modified INTEGER NOT NULL,
            creator REFERENCES users(username),
            last_set_by NULL REFERENCES users(username)
        );

        CREATE TABLE grants (
            grantee REFERENCES users(username),
            service_name REFERENCES services(service_name),
            created INTEGER NOT NULL,
            grantor REFERENCES users(username),
            ciphertext, -- encrypted by grantor's secret key to grantee's public key
            signature, -- signed by grantor's public key
            PRIMARY KEY(grantee, service_name)
        );
        CREATE INDEX grants_services ON grants(service_name);
    "));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use sodiumoxide::crypto::box_;
    use sodiumoxide::crypto::sign;
    use tempdir;

    #[test]
    pub fn test_server() {
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

        debug!("Creating users");
        let (d_public_key, d_private_key) = box_::gen_keypair();
        let (d_public_sign, d_private_sign) = sign::gen_keypair();
        let david = server.create_user("david".to_string(),
                                       "david_fingerprint".to_string(),
                                       d_public_key,
                                       d_public_sign).unwrap();
        let authenticated = server.authenticate(&"david".to_string(),
                                                &"david_fingerprint".to_string()).unwrap();
        assert_eq!(david.username, authenticated.username);

        let (f_public_key, private_key) = box_::gen_keypair();
        let (f_public_sign, private_sign) = sign::gen_keypair();
        let florence = server.create_user("florence".to_string(),
                                          "florence_fingerprint".to_string(),
                                          f_public_key,
                                          f_public_sign).unwrap();

        server.create_service("service1".to_string(),
                              &david,
                              "ciphertext".as_bytes().to_vec()).unwrap();

        // david will need to get Florence's public key first
        let florence = server.get_user(&"florence".to_string()).unwrap();
        let signed = sign::sign_detached(&"ciphertext".as_bytes(),
                                         &d_private_sign);

        server.rotate_service("service1".to_string(),
                              &david,
                              &[(&florence,
                                 &"ciphertext".as_bytes().to_vec(),
                                 &signed)
                               ]).unwrap();

        // now florence should be able to find that and get the grant
        let grant = server.get_grant("service1".to_string(),
                                     &florence).unwrap();
        assert_eq!(grant.ciphertext, "ciphertext".as_bytes().to_vec());
    }
}
