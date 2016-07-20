use std::path::Path;

use chrono::UTC;
use rusqlite;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;

use api::{User, Service, Grant, JoinRequest, PeerInfo};
use common;
use common::SecretsContainer;
use common::SecretsError;
use keys;
use utils;

const SYNC_SLOP: i64 = 60; // in seconds

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
        let mut server = SecretsServer {
            db: db,
            password: password,
        };
        try!(server.create_and_store_keys(&cn));

        Ok(server)
    }

    pub fn connect<P: AsRef<Path>>(config_file: P,
                                   password: String)
                                   -> Result<Self, SecretsError> {
        let db = try!(common::connect_db(config_file));
        let instance = SecretsServer {
            db: db,
            password: password,
        };
        return Ok(instance);
    }

    // called interactively
    pub fn accept_join(&mut self,
                       jr: JoinRequest)
                       -> Result<User, SecretsError> {
        if jr.server_info != try!(self.get_peer_info()) {
            return Err(SecretsError::Authentication("server_info doesn't \
                                                     match"));
        }

        if try!(self.user_exists(&jr.client_info.cn)) {
            return Err(SecretsError::Authentication("user exists"));
        }

        println!("=== client info: ===\n{}",
                 try!(jr.client_info.printable_report()));

        let accepted = try!(utils::prompt_yn("does that look right? [y/n] "));
        if !accepted {
            return Err(SecretsError::Authentication("refused client \
                                                     authenticator"));
        }

        let user = try!(self.create_user(jr.client_info.cn,
                                         jr.client_info.fingerprint,
                                         jr.client_info.public_key,
                                         jr.client_info.public_sign));
        info!("created user: {}", user.username);
        return Ok(user);
    }

    fn create_user(&self,
                   username: String,
                   ssl_fingerprint: String,
                   public_key: box_::PublicKey,
                   public_sign: sign::PublicKey)
                   -> Result<User, SecretsError> {
        let now = UTC::now().timestamp();
        try!(self.db.execute("
            INSERT INTO users(username, ssl_fingerprint,
                              public_key, public_sign,
                              created)
            VALUES(?,?,?,?,?)
            ",
            &[&username,
              &ssl_fingerprint,
              &public_key.as_ref(),
              &public_sign.as_ref(),
              &now]));
        let user = try!(self.get_user(&username));
        return Ok(user);
    }

    pub fn get_user(&self, username: &String) -> Result<User, SecretsError> {
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
            Err(SecretsError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                Ok(false)
            }
            Err(x) => Err(x),
        }
    }

    pub fn authenticate(&self,
                        username: &String,
                        ssl_fingerprint: &String)
                        -> Result<User, SecretsError> {
        let user = match self.get_user(username) {
            Ok(user) => user,
            Err(SecretsError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                return Err(SecretsError::Authentication("no user"))
            }
            Err(x) => return Err(x),
        };
        if !utils::constant_time_compare(&user.ssl_fingerprint.as_bytes(),
                                         &ssl_fingerprint.as_bytes()) {
            return Err(SecretsError::Authentication("bad fingerprint match"));
        }
        if user.disabled.is_some() {
            return Err(SecretsError::Authentication("user is disabled"));
        }
        return Ok(user);
    }

    pub fn get_service(&self,
                       service_name: &String)
                       -> Result<Service, SecretsError> {
        let service = try!(self.db.query_row_and_then("
            SELECT service_name, created, modified, creator, modified_by
            FROM services
            WHERE service_name=?
            ",
            &[service_name],
            Service::from_row));
        return Ok(service);
    }

    pub fn service_exists(&self,
                          service_name: &String)
                          -> Result<bool, SecretsError> {
        match self.get_service(service_name) {
            Ok(_) => Ok(true),
            Err(SecretsError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                Ok(false)
            }
            Err(x) => Err(x),
        }
    }

    pub fn create_service(&mut self,
                          auth_user: &User,
                          service: Service,
                          grants: Vec<Grant>)
                          -> Result<(), SecretsError> {
        // the client has to create the timestamps in order to include them in
        // the signature, but we want them to be able to lie about them. So
        // check all of the timestamps and allow minimal slop
        let now = UTC::now().timestamp();

        // make sure we have the most up-to-date version
        let auth_user = try!(self.get_user(&auth_user.username));

        if !grants.iter().any(|g| g.grantee == auth_user.username) {
            return Err(SecretsError::ServerError("you must grant yourself"
                .to_string()));
        }
        if try!(self.service_exists(&service.name)) {
            return Err(SecretsError::ServiceAlreadyExists(service.name
                .clone()));
        }

        if auth_user.disabled.is_some() {
            return Err(SecretsError::Authentication("disabled user can't grant"));
        }

        for ref grant in &grants {
            let grantee_user = try!(self.get_user(&grant.grantee));
            if grantee_user.disabled.is_some() {
                return Err(SecretsError::Authentication("can't grant to \
                                                         disabled user"));
            }
        }

        let trans = try!(self.db.transaction());
        try!(Self::_create_service(&trans, now, &auth_user, &service));
        for grant in grants {
            try!(Self::_create_grant(&trans, now, &auth_user, &service, grant));
        }
        try!(trans.commit());

        Ok(())
    }

    fn _create_service(trans: &rusqlite::Transaction,
                       now: i64,
                       auth_user: &User,
                       service: &Service)
                       -> Result<(), SecretsError> {
        if (now - service.modified).abs() > SYNC_SLOP ||
           (now - service.created).abs() > SYNC_SLOP {
            return Err(SecretsError::ServerError("clock sync".to_string()));
        }
        if service.creator != auth_user.username ||
           service.modified_by != auth_user.username {
            return Err(SecretsError::ServerError("you're lying".to_string()));
        }

        try!(trans.execute("
            INSERT INTO services(service_name, created, modified,
                                 creator, modified_by)
            VALUES(?,?,?,?,?)
            ",
            &[&service.name,
              &service.created,
              &service.modified,
              &service.creator,
              &service.modified_by]));

        Ok(())
    }

    fn _create_grant(trans: &rusqlite::Transaction,
                     now: i64,
                     auth_user: &User,
                     service: &Service,
                     grant: Grant)
                     -> Result<(), SecretsError> {
        if (now - grant.created).abs() > SYNC_SLOP {
            return Err(SecretsError::ServerError("clock sync".to_string()));
        }
        if grant.grantor != auth_user.username {
            return Err(SecretsError::ServerError("you're lying".to_string()));
        }
        if service.name != grant.service_name {
            return Err(SecretsError::ServerError("malformed request"
                .to_string()));
        }

        try!(trans.execute("
            INSERT INTO grants(service_name, grantor, grantee, ciphertext,
                        signature, created)
            VALUES (?,?,?,?,?,?)
            ",
            &[&grant.service_name,
              &grant.grantor,
              &grant.grantee,
              &grant.ciphertext,
              &grant.signature.as_ref(),
              &now]));
        Ok(())
    }

    pub fn rotate_service(&mut self,
                          service_name: String,
                          grantor: &User,
                          grants: &[(&User, &Vec<u8>, &sign::Signature)])
                          -> Result<(), SecretsError> {
        // make sure the service exists
        let service = try!(self.get_service(&service_name));
        let now = UTC::now().timestamp();
        let trans = try!(self.db.transaction());
        try!(trans.execute_batch("
            CREATE TEMPORARY TABLE new_grants(grantee PRIMARY KEY)
        "));
        for &(ref grantee, ref ciphertext, ref signature) in grants {
            if grantee.disabled.is_some() {
                return Err(SecretsError::Authentication("can't grant to \
                                                         disabled user"));
            }
            // make sure the signature matches
            if !sign::verify_detached(&signature,
                                      ciphertext,
                                      &grantor.public_sign) {
                return Err(SecretsError::Crypto(keys::CryptoError::CantDecrypt));
            }
            try!(trans.execute("
                INSERT INTO new_grants(grantee) VALUES(?)
                ",
                &[&grantee.username]));
            try!(trans.execute("
                INSERT OR REPLACE INTO grants(grantor, grantee,
                                              service_name, created,
                                              ciphertext, signature)
                VALUES (?, ?, ?, ?, ?, ?)
                ",
                &[&grantor.username,
                  &grantee.username,
                  &service.name,
                  &now,
                  *ciphertext,
                  &signature.as_ref()]));
            try!(trans.execute("
                UPDATE services SET modified=?, modified_by=?
                ",
                &[&now, &grantor.username]));
            try!(trans.execute_batch("
                DELETE FROM grants
                WHERE grantee NOT IN (SELECT grantee FROM new_grants);
            "));
        }
        try!(trans.commit());
        return Ok(());
    }

    pub fn get_grant(&self,
                     service_name: &String,
                     grantee_name: &String)
                     -> Result<Grant, SecretsError> {
        let grant = try!(self.db.query_row_and_then("
            SELECT service_name, grantee, grantor, ciphertext, signature,
                   created
            FROM grants
            WHERE service_name = ? AND grantee = ?
            ",
            &[service_name,
              grantee_name],
              Grant::from_row));
        // verify the signature on the grant
        let grantor = try!(self.get_user(&grant.grantor));
        if !sign::verify_detached(&grant.signature,
                                  &grant.ciphertext,
                                  &grantor.public_sign) {
            return Err(SecretsError::Crypto(keys::CryptoError::CantDecrypt));
        }
        return Ok(grant);
    }

    pub fn get_peer_info(&self) -> Result<PeerInfo, SecretsError> {
        // TODO we're really not storing the CN in a global?
        let cn = try!(self.ssl_cn());
        let fingerprint = try!(self.ssl_fingerprint());

        let (public_key, _) = try!(self.get_keys());
        let (public_sign, _) = try!(self.get_signs());

        return Ok(PeerInfo {
            cn: cn,
            fingerprint: fingerprint,
            public_key: public_key,
            public_sign: public_sign,
        });
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

fn create_server_schema(conn: &mut rusqlite::Connection)
                        -> Result<(), rusqlite::Error> {
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
            creator NOT NULL REFERENCES users(username),
            modified_by NOT NULL REFERENCES users(username)
        );

        CREATE TABLE grants (
            grantee NOT NULL REFERENCES users(username),
            service_name NOT NULL REFERENCES services(service_name),
            created INTEGER NOT NULL,
            grantor NOT NULL REFERENCES users(username),
            ciphertext NOT NULL, -- encrypted to grantee's public key
            signature NOT NULL, -- signed by grantor's public key
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
        let password = "hello".to_string();
        let cn = "me.local".to_string();
        let mut tempfile = dir.into_path();
        tempfile.push("server.db");

        debug!("Creating");
        let created =
            SecretsServer::create(&tempfile, password.to_string(), cn).unwrap();
        drop(created);

        debug!("Connecting");
        let server = SecretsServer::connect(tempfile, password.to_string())
            .unwrap();

        debug!("Creating users");
        let (d_public_key, _d_private_key) = box_::gen_keypair();
        let (d_public_sign, _d_private_sign) = sign::gen_keypair();
        let david = server.create_user("david".to_string(),
                         "david_fingerprint".to_string(),
                         d_public_key,
                         d_public_sign)
            .unwrap();
        let authenticated = server.authenticate(&"david".to_string(),
                          &"david_fingerprint".to_string())
            .unwrap();
        assert_eq!(david.username, authenticated.username);

        let (f_public_key, _f_private_key) = box_::gen_keypair();
        let (f_public_sign, _f_private_sign) = sign::gen_keypair();
        let _florence = server.create_user("florence".to_string(),
                         "florence_fingerprint".to_string(),
                         f_public_key,
                         f_public_sign)
            .unwrap();
    }
}
