use std::path::Path;

use chrono::offset::Utc;
use rusqlite;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;

use api::{Grant, JoinRequest, PeerInfo, Service, User};
use common;
use common::SecretsContainer;
use common::SecretsError;
use utils;

const SYNC_SLOP: i64 = 60; // in seconds

pub struct SecretsServer {
    db: rusqlite::Connection,
    password: String,
}

impl SecretsServer {
    pub fn create<P: AsRef<Path>>(
        config_file: P,
        cn: String,
        password: String,
    ) -> Result<Self, SecretsError> {
        let mut db = common::create_db(config_file)?;
        create_server_schema(&mut db)?;
        let mut server = SecretsServer {
            db: db,
            password: password,
        };
        server.create_and_store_keys(&cn)?;

        Ok(server)
    }

    pub fn connect<P: AsRef<Path>>(
        config_file: P,
        password: String,
    ) -> Result<Self, SecretsError> {
        let db = common::connect_db(config_file)?;
        let instance = SecretsServer {
            db: db,
            password: password,
        };
        Ok(instance)
    }

    // called interactively
    pub fn accept_join(
        &mut self,
        jr: JoinRequest,
    ) -> Result<User, SecretsError> {
        if jr.server_info != self.get_peer_info()? {
            return Err(SecretsError::Authentication(
                "server_info doesn't match",
            ));
        }

        if self.user_exists(&jr.client_info.cn)? {
            return Err(SecretsError::Authentication("user exists"));
        }

        println!("{}", jr.client_info.printable_report()?);

        let accepted = utils::prompt_yn("does that look right? [y/n] ")?;
        if !accepted {
            return Err(SecretsError::Authentication("refused"));
        }

        let user = self.create_user(
            jr.client_info.cn,
            jr.client_info.fingerprint,
            jr.client_info.public_key,
            jr.client_info.public_sign,
        )?;
        info!("created user: {}", user.username);
        Ok(user)
    }

    fn create_user(
        &self,
        username: String,
        ssl_fingerprint: String,
        public_key: box_::PublicKey,
        public_sign: sign::PublicKey,
    ) -> Result<User, SecretsError> {
        let now = Utc::now().timestamp();
        self.db.execute(
            "INSERT INTO users(username, ssl_fingerprint,
                               public_key, public_sign,
                               created)
             VALUES(?,?,?,?,?)
            ",
            &[
                &username,
                &ssl_fingerprint,
                &public_key.as_ref(),
                &public_sign.as_ref(),
                &now,
            ],
        )?;
        let user = self.get_user(&username)?;
        Ok(user)
    }

    pub fn fire_user(
        &self,
        username: &str,
        force: bool,
    ) -> Result<FireResult, SecretsError> {
        let now = Utc::now().timestamp();
        let user = self.get_user(username)?;
        let granted_services = self.get_grants_for_grantee(username)?;

        // by design, any passwords that the user might know should be returned
        // by this. this is why we enforce that new services and rotations must
        // always include the person setting the new secret
        if !force && !granted_services.is_empty() {
            return Ok(FireResult::OutstandingGrants {
                grants: granted_services,
            });
        }

        if user.disabled.is_none() {
            // if they weren't already disabled, mark the time.
            self.db.execute(
                "UPDATE users SET disabled=? WHERE username=?",
                &[&now, &username],
            )?;
        }

        Ok(FireResult::Success)
    }

    pub fn get_user(&self, username: &str) -> Result<User, SecretsError> {
        let user = self.db.query_row_and_then(
            "SELECT username, public_key, public_sign, ssl_fingerprint,
                    created, disabled
             FROM users
             WHERE username=?
            ",
            &[&username],
            User::from_row,
        )?;
        Ok(user)
    }

    fn user_exists(&self, username: &str) -> Result<bool, SecretsError> {
        match self.get_user(username) {
            Ok(_) => Ok(true),
            Err(SecretsError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                Ok(false)
            }
            Err(x) => Err(x),
        }
    }

    pub fn authenticate(
        &self,
        username: &str,
        ssl_fingerprint: &str,
    ) -> Result<User, SecretsError> {
        let user = match self.get_user(username) {
            Ok(user) => user,
            Err(SecretsError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                return Err(SecretsError::Authentication("no user"))
            }
            Err(x) => return Err(x),
        };
        if !utils::constant_time_compare(
            user.ssl_fingerprint.as_bytes(),
            ssl_fingerprint.as_bytes(),
        ) {
            return Err(SecretsError::Authentication("bad fingerprint match"));
        }
        if user.disabled.is_some() {
            return Err(SecretsError::Authentication("user is disabled"));
        }
        Ok(user)
    }

    pub fn get_service(
        &self,
        service_name: &str,
    ) -> Result<Service, SecretsError> {
        let service = self.db.query_row_and_then(
            "SELECT service_name, created, modified, creator, modified_by
                 FROM services
                 WHERE service_name=?
                 ",
            &[&service_name],
            |r| Service::from_row(r),
        )?;
        Ok(service)
    }

    pub fn all_services(&self) -> Result<Vec<Service>, SecretsError> {
        let mut ret = vec![];
        let mut stmt = self.db.prepare(
            "SELECT service_name, created, modified, creator, modified_by
             FROM services
            ",
        )?;
        let services = stmt.query_and_then(&[], |r| Service::from_row(r))?;
        for maybe_service in services {
            let service = maybe_service?;
            ret.push(service)
        }
        Ok(ret)
    }

    pub fn service_exists(
        &self,
        service_name: &str,
    ) -> Result<bool, SecretsError> {
        match self.get_service(service_name) {
            Ok(_) => Ok(true),
            Err(SecretsError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                Ok(false)
            }
            Err(x) => Err(x),
        }
    }

    pub fn create_service(
        &mut self,
        auth_user: &User,
        service: Service,
        grants: Vec<Grant>,
    ) -> Result<(), SecretsError> {
        // the client has to create the timestamps in order to include them in
        // the signature, but we want them to be able to lie about them. So
        // check all of the timestamps and allow minimal slop
        let now = Utc::now().timestamp();

        // make sure we have the most up-to-date version
        let auth_user = self.get_user(&auth_user.username)?;

        if !grants.iter().any(|g| g.grantee == auth_user.username) {
            return Err(SecretsError::ServerError(
                "you must grant yourself".to_string(),
            ));
        }
        if self.service_exists(&service.name)? {
            return Err(SecretsError::ServiceAlreadyExists(
                service.name.clone(),
            ));
        }

        if auth_user.disabled.is_some() {
            return Err(SecretsError::Authentication(
                "disabled user can't grant",
            ));
        }

        for grant in &grants {
            let grantee_user = self.get_user(&grant.grantee)?;
            if grantee_user.disabled.is_some() {
                return Err(SecretsError::Authentication(
                    "can't grant to \
                     disabled user",
                ));
            }
        }

        let trans = self.db.transaction()?;
        Self::_create_service(&trans, now, &auth_user, &service)?;
        for grant in grants {
            Self::_create_grant(&trans, now, &auth_user, &service, grant)?;
        }
        trans.commit()?;

        Ok(())
    }

    fn _create_service(
        trans: &rusqlite::Transaction,
        now: i64,
        auth_user: &User,
        service: &Service,
    ) -> Result<(), SecretsError> {
        if (now - service.modified).abs() > SYNC_SLOP
            || (now - service.created).abs() > SYNC_SLOP
        {
            return Err(SecretsError::ServerError("clock sync".to_string()));
        }
        if service.creator != auth_user.username
            || service.modified_by != auth_user.username
        {
            return Err(SecretsError::ServerError("you're lying".to_string()));
        }

        trans.execute(
            "INSERT INTO services(service_name, created, modified,
                                  creator, modified_by)
             VALUES(?,?,?,?,?)
            ",
            &[
                &service.name,
                &service.created,
                &service.modified,
                &service.creator,
                &service.modified_by,
            ],
        )?;

        Ok(())
    }

    fn _create_grant(
        trans: &rusqlite::Transaction,
        now: i64,
        auth_user: &User,
        service: &Service,
        grant: Grant,
    ) -> Result<(), SecretsError> {
        if (now - grant.created).abs() > SYNC_SLOP {
            return Err(SecretsError::ServerError("clock sync".to_string()));
        }
        if grant.grantor != auth_user.username {
            return Err(SecretsError::ServerError("you're lying".to_string()));
        }
        if service.name != grant.service_name {
            return Err(SecretsError::ServerError(
                "malformed request".to_string(),
            ));
        }
        if auth_user.disabled.is_some() {
            return Err(SecretsError::Authentication(
                "disabled user can't grant",
            ));
        }

        grant.verify_signature(&auth_user.public_sign)?;

        trans.execute(
            "INSERT OR IGNORE -- TODO ignore is best?
             INTO grants(service_name, grantor, grantee, ciphertext,
                         signature, created)
             VALUES (?,?,?,?,?,?)
            ",
            &[
                &grant.service_name,
                &grant.grantor,
                &grant.grantee,
                &grant.ciphertext,
                &grant.signature.as_ref(),
                &grant.created,
            ],
        )?;
        Ok(())
    }

    fn _touch_service(
        trans: &rusqlite::Transaction,
        now: i64,
        auth_user: &User,
        service: &Service,
    ) -> Result<(), SecretsError> {
        trans.execute(
            "UPDATE services
             SET modified_by=?, modified=?
             WHERE service_name=?
            ",
            &[&auth_user.username, &now, &service.name],
        )?;
        Ok(())
    }

    pub fn get_grants_for_service(
        &self,
        service_name: &str,
    ) -> Result<Vec<Grant>, SecretsError> {
        let mut ret = vec![];
        let _: Service = self.get_service(service_name)?;
        let mut stmt = self.db.prepare(
            "SELECT service_name, grantee, grantor, ciphertext, signature,
                    created
             FROM grants
             WHERE service_name = ?
            ",
        )?;
        let grants =
            stmt.query_and_then(&[&service_name], |r| Grant::from_row(r))?;
        for maybe_grant in grants {
            let grant = maybe_grant?;
            // verify the signature so we don't return invalid grants
            let grantor = self.get_user(&grant.grantor)?;
            grant.verify_signature(&grantor.public_sign)?;

            ret.push(grant);
        }

        Ok(ret)
    }

    pub fn get_grants_for_grantee(
        &self,
        grantee_name: &str,
    ) -> Result<Vec<Grant>, SecretsError> {
        let mut ret = vec![];
        let _: User = self.get_user(grantee_name)?;
        let mut stmt = self.db.prepare(
            "SELECT service_name, grantee, grantor, ciphertext, signature,
                    created
             FROM grants
             WHERE grantee = ?
            ",
        )?;
        let grants =
            stmt.query_and_then(&[&grantee_name], |r| Grant::from_row(r))?;
        for maybe_grant in grants {
            let grant = maybe_grant?;
            // verify the signature so we don't return invalid grants
            let grantor = self.get_user(&grant.grantor)?;
            grant.verify_signature(&grantor.public_sign)?;

            ret.push(grant);
        }

        Ok(ret)
    }

    pub fn add_grants(
        &mut self,
        auth_user: &User,
        service_name: &str,
        grants: Vec<Grant>,
    ) -> Result<(), SecretsError> {
        let service = self.get_service(service_name)?;
        let now = Utc::now().timestamp();

        // make sure we have the most up-to-date version
        let auth_user = self.get_user(&auth_user.username)?;

        // make sure that they actually hold the password that they are adding
        // additional grants for. If they don't, they should be rotating instead
        // and it's important that we enforce that difference
        let _: Grant = self.get_grant(service_name, &auth_user.username)?;

        let trans = self.db.transaction()?;
        for grant in grants {
            Self::_create_grant(&trans, now, &auth_user, &service, grant)?;
        }
        trans.commit()?;
        Ok(())
    }

    pub fn rotate_service(
        &mut self,
        auth_user: &User,
        service_name: &str,
        grants: Vec<Grant>,
    ) -> Result<(), SecretsError> {
        let service = self.get_service(service_name)?;
        let now = Utc::now().timestamp();

        // make sure we have the most up-to-date version
        let auth_user = self.get_user(&auth_user.username)?;

        if !grants.iter().any(|g| g.grantee == auth_user.username) {
            return Err(SecretsError::ServerError(
                "you must grant yourself".to_string(),
            ));
        }

        let trans = self.db.transaction()?;

        // delete all of the previous grants
        trans.execute(
            "DELETE FROM grants WHERE service_name=?",
            &[&service_name],
        )?;
        // add the new ones
        for grant in grants {
            Self::_create_grant(&trans, now, &auth_user, &service, grant)?;
        }
        Self::_touch_service(&trans, now, &auth_user, &service)?;
        trans.commit()?;

        Ok(())
    }

    pub fn get_grant(
        &self,
        service_name: &str,
        grantee_name: &str,
    ) -> Result<Grant, SecretsError> {
        let grant = self.db.query_row_and_then(
            "SELECT service_name, grantee, grantor, ciphertext, signature,
                    created
             FROM grants
             WHERE service_name = ? AND grantee = ?
            ",
            &[&service_name, &grantee_name],
            |r| Grant::from_row(r),
        )?;

        // verify the signature so we don't return invalid grants
        let grantor = self.get_user(&grant.grantor)?;
        grant.verify_signature(&grantor.public_sign)?;

        Ok(grant)
    }

    pub fn get_peer_info(&self) -> Result<PeerInfo, SecretsError> {
        // TODO we're really not storing the CN in a global?
        let cn = self.ssl_cn()?;
        let fingerprint = self.ssl_fingerprint()?;

        let (public_key, _) = self.get_keys()?;
        let (public_sign, _) = self.get_signs()?;

        Ok(PeerInfo {
            cn: cn,
            fingerprint: fingerprint,
            public_key: public_key,
            public_sign: public_sign,
        })
    }
}

impl SecretsContainer for SecretsServer {
    fn get_db(&self) -> &rusqlite::Connection {
        &self.db
    }

    fn get_password(&self) -> &str {
        &self.password
    }
}

#[derive(PartialEq, Debug)]
pub enum FireResult {
    Success,
    OutstandingGrants { grants: Vec<Grant> },
}

fn create_server_schema(
    conn: &mut rusqlite::Connection,
) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
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
        ",
    )?;

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
        let server =
            SecretsServer::connect(tempfile, password.to_string()).unwrap();

        debug!("Creating users");
        let (d_public_key, _d_private_key) = box_::gen_keypair();
        let (d_public_sign, _d_private_sign) = sign::gen_keypair();
        let david = server
            .create_user(
                "david".to_string(),
                "david_fingerprint".to_string(),
                d_public_key,
                d_public_sign,
            )
            .unwrap();
        let authenticated = server
            .authenticate(
                &"david".to_string(),
                &"david_fingerprint".to_string(),
            )
            .unwrap();
        assert_eq!(david.username, authenticated.username);

        let (f_public_key, _f_private_key) = box_::gen_keypair();
        let (f_public_sign, _f_private_sign) = sign::gen_keypair();
        let _florence = server
            .create_user(
                "florence".to_string(),
                "florence_fingerprint".to_string(),
                f_public_key,
                f_public_sign,
            )
            .unwrap();
    }
}
