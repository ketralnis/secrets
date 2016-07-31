use std::collections::HashMap;
use std::io::Write;
use std::io;
use std::path::Path;
use std::sync::Arc;

use chrono::UTC;
use hyper::method::Method;
use hyper::net::HttpsConnector;
use hyper::net::Openssl;
use hyper::status::StatusCode;
use hyper::Url;
use hyper;
use openssl::crypto::hash::Type as HashType;
use openssl::nid::Nid;
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::ssl::{SSL_VERIFY_NONE, SSL_VERIFY_PEER, SSL_OP_NO_SSLV2,
                   SSL_OP_NO_SSLV3, SSL_OP_NO_COMPRESSION};
use openssl::x509::X509StoreContext;
use rusqlite;
use rustc_serialize::hex::ToHex;
use serde::ser::Serialize;
use serde_json::from_reader as dejson_from_reader;
use serde_json::ser::to_vec as json_to_vec;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use url::form_urlencoded::Serializer as QueryStringSerializer;

use api::{ApiResponse, PeerInfo, JoinRequest, Service, Grant,
          ServiceCreateRequest, GrantRequest, User};
use common;
use common::SecretsContainer;
use common::SecretsError;
use keys;
use utils;

pub struct SecretsClient {
    db: rusqlite::Connection,
    password: String,
}

impl SecretsClient {
    /// create a new local database and connect to the server to get
    /// its various keys
    pub fn create<P: AsRef<Path>>(config_file: P,
                                  host: String,
                                  username: String,
                                  password: String)
                                  -> Result<Self, SecretsError> {
        // Because we aren't really set up yet, we have to do a lot by hand that
        // the normal client can just do through convenience methods

        // this SSL verifier will not check fingerprints, because we don't know
        // the remote fingerprint yet. In addition, the server tells us its
        // fingerprint in the JSON payload, rather than verifying that that
        // fingerprint we connected to is the same. That's okay because all
        // future connections will check against whatever fingerprint they give
        // us. So if they give us a fake fingerprint, when we ask the user they
        // will reject it. If they lie about controlling this fingerprint, then
        // any future connections to them will fail anyway.
        let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1));
        ssl_context.set_verify(SSL_VERIFY_NONE, None);
        ssl_context.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 |
                                SSL_OP_NO_COMPRESSION);
        try!(ssl_context.set_cipher_list(
            "ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4@STRENGTH"));
        let ssl = Openssl { context: Arc::new(ssl_context) };
        let connector = HttpsConnector::new(ssl);
        let http = hyper::Client::with_connector(connector);

        // this will connect via that configured SSL client which will record
        // the server's fingerprint and CN into the recorder
        let info_url = http_path(&host, "/api/server");
        info!("connecting to {}", info_url);
        let response = try!(http.get(&info_url).send());
        if response.status != hyper::Ok {
            return Err(SecretsError::ClientError(format!("unknown status {}",
                                                         response.status)));
        }

        let api_response: ApiResponse = try!(dejson_from_reader(response));
        let server_info = try!(api_response.server_info
            .ok_or(SecretsError::ClientError("missing server info"
                .to_string())));

        let server_report = try!(server_info.printable_report());
        try!(io::stderr().write(server_report.as_bytes()));

        if !try!(utils::prompt_yn("does that look right? [y/n] ")) {
            return Err(SecretsError::Authentication("refused"));
        }

        info!("creating client DB");

        let mut db = try!(common::create_db(config_file));
        try!(create_client_schema(&mut db));

        let mut client = SecretsClient {
            db: db,
            password: password,
        };

        try!(client.create_and_store_keys(&username));
        try!(client.set_global("username", &username));
        try!(client.set_global("server_host", &host));
        try!(client.set_global("server_fingerprint", &server_info.fingerprint));
        try!(client.set_global("server_cn", &server_info.cn));
        try!(client.set_global("server_public_key",
                               &server_info.public_key.as_ref()));
        try!(client.set_global("server_public_sign",
                               &server_info.public_sign.as_ref()));

        return Ok(client);
    }

    pub fn join_request(&self) -> Result<JoinRequest, SecretsError> {
        info!("creating join request");

        let server_info = try!(self.get_server_info());
        let client_info = try!(self.get_peer_info());
        let join_request = JoinRequest {
            server_info: server_info,
            client_info: client_info,
        };
        return Ok(join_request);
    }

    pub fn get_server_info(&self) -> Result<PeerInfo, SecretsError> {
        let cn = try!(self.get_global::<String>("server_cn"));
        let fingerprint = try!(self.get_global::<String>("server_fingerprint"));

        let public_key_vec: Vec<u8> =
            try!(self.get_global("server_public_key"));
        let public_key = box_::PublicKey::from_slice(&public_key_vec);
        let public_key = try!(public_key.ok_or(keys::CryptoError::Unknown));

        let public_sign_vec: Vec<u8> =
            try!(self.get_global("server_public_sign"));
        let public_sign = sign::PublicKey::from_slice(&public_sign_vec);
        let public_sign = try!(public_sign.ok_or(keys::CryptoError::Unknown));

        return Ok(PeerInfo {
            cn: cn,
            fingerprint: fingerprint,
            public_key: public_key,
            public_sign: public_sign,
        });
    }

    pub fn get_peer_info(&self) -> Result<PeerInfo, SecretsError> {
        let cn = try!(self.username());
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

    pub fn check_server(&self) -> Result<(), SecretsError> {
        let req = SecretsRequest::new(Method::Get, "/api/auth");
        let api_response = try!(self.server_request(req));
        let username = try!(self.username());
        if !api_response.users
            .iter()
            .any(|(_, user)| *user.username == username) {
            return Err(SecretsError::ClientError("how come I'm not in here?"
                .to_string()));
        }
        return Ok(());
    }

    fn server_request(&self,
                      req: SecretsRequest)
                      -> Result<ApiResponse, SecretsError> {
        // set up the SSL verifier to check the fingerprint
        let (public_pem, private_pem) = try!(self.get_pems());
        let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1));
        ssl_context.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 |
                                SSL_OP_NO_COMPRESSION);
        try!(ssl_context.set_cipher_list(
            "ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4@STRENGTH"));
        try!(ssl_context.set_certificate(&public_pem));
        try!(ssl_context.set_private_key(&private_pem));
        try!(ssl_context.check_private_key());

        let server_fingerprint =
            try!(self.get_global::<String>("server_fingerprint"));
        let server_cn = try!(self.get_global::<String>("server_cn"));
        ssl_context.set_verify_with_data(SSL_VERIFY_PEER,
                                         verify_ssl_fingerprint,
                                         (server_fingerprint, server_cn));

        let ssl = Openssl { context: Arc::new(ssl_context) };
        let connector = HttpsConnector::new(ssl);
        let http_client = hyper::Client::with_connector(connector);
        let host = try!(self.get_global::<String>("server_host"));

        let mut url = try!(Url::parse(&http_path(&host, req.path)));

        let response = try!(match (req.method, req.json) {
            (Method::Get, None) => {
                let mut qss = QueryStringSerializer::new(String::new());
                qss.extend_pairs(&req.arguments);
                let qss = qss.finish();
                url.set_query(Some(&qss));
                let request_builder = http_client.get(url);
                request_builder.send()
            }
            (Method::Post, None) => http_client.post(url).send(),
            (Method::Post, Some(json_value)) => {
                let json_str = json_value;
                http_client.post(url)
                    .body(&json_str[..])
                    .send()
            }
            _ => unreachable!(),
        });

        if response.status != StatusCode::Ok {
            return Err(SecretsError::ClientError(format!("got an error from the server ({}): {}",
                                                         req.path,
                                                         response.status)));
        }
        let api_response: ApiResponse = try!(dejson_from_reader(response));
        if let Some(err) = api_response.error {
            return Err(SecretsError::ClientError(err));
        }
        return Ok(api_response);
    }

    pub fn connect<P: AsRef<Path>>(config_file: P,
                                   password: String)
                                   -> Result<Self, SecretsError> {
        let db = try!(common::connect_db(config_file));
        let client = SecretsClient {
            db: db,
            password: password,
        };
        try!(client.check_db());
        try!(client.get_keys()); // this effectively checks their password
        return Ok(client);
    }

    pub fn username(&self) -> Result<String, SecretsError> {
        let username = try!(self.get_global::<String>("username"));
        return Ok(username);
    }

    pub fn create_service(&mut self,
                          service_name: String,
                          plaintext: Vec<u8>,
                          grantees: Vec<String>)
                          -> Result<(), SecretsError> {
        // make sure the service doesn't exist and look up the users that we'll
        // grant to to get their keys
        let mut req = SecretsRequest::new(Method::Get, "/api/info");
        req.add_arg("service", service_name.clone());
        for grantee_name in &grantees {
            req.add_arg("user", grantee_name.clone());
        }
        let api_response = try!(self.server_request(req));

        if api_response.services.len() > 0 {
            return Err(SecretsError::ServiceAlreadyExists(service_name));
        }

        let now = UTC::now().timestamp();
        let username = try!(self.username());

        let service = Service {
            name: service_name.clone(),
            created: now,
            modified: now,
            creator: username.clone(),
            modified_by: username.clone(),
        };

        let grants = try!(self._create_grants(plaintext,
                                              &service_name,
                                              now,
                                              grantees,
                                              api_response.users));

        let service_creator = ServiceCreateRequest {
            service: service,
            grants: grants,
        };

        let mut create_req = SecretsRequest::new(Method::Post,
                                                 "/api/create-service");
        try!(create_req.set_json(service_creator));
        try!(self.server_request(create_req));

        return Ok(());
    }

    fn _create_grants(&self,
                      plaintext: Vec<u8>,
                      service_name: &String,
                      now: i64,
                      grantee_names: Vec<String>,
                      grantee_map: HashMap<String, User>)
                      -> Result<Vec<Grant>, SecretsError> {
        let username = try!(self.username());
        let (_, private_key) = try!(self.get_keys());
        let (public_sign, private_sign) = try!(self.get_signs());
        let mut grants = vec![];

        for grantee_name in grantee_names {
            if let Some(grantee) = grantee_map.get(&grantee_name) {
                let grant = try!(Grant::create(grantee_name,
                                               username.clone(),
                                               service_name.clone(),
                                               &plaintext,
                                               now,
                                               &private_key,
                                               &grantee.public_key,
                                               &private_sign));
                // make sure the signature checks out to catch sig issues
                // earlier in the process
                debug_assert!(grant.verify_signature(&public_sign).is_ok());
                grants.push(grant);
            } else {
                return Err(SecretsError::UserDoesntExist(grantee_name));
            }
        }

        return Ok(grants);
    }

    pub fn get_user(&self, username: &String) -> Result<User, SecretsError> {
        let mut req = SecretsRequest::new(Method::Get, "/api/info");
        req.add_arg("user", username.clone());

        let mut api_response = try!(self.server_request(req));

        let user = try!(api_response.users
            .remove(username)
            .ok_or(SecretsError::ClientError("user not found".to_string())));
        return Ok(user);
    }

    pub fn get_service(&self,
                       service_name: &String)
                       -> Result<Service, SecretsError> {
        let mut req = SecretsRequest::new(Method::Get, "/api/info");
        req.add_arg("service", service_name.clone());

        let mut api_response = try!(self.server_request(req));

        let service = try!(api_response.services
            .remove(service_name)
            .ok_or(SecretsError::ClientError("service not found".to_string())));
        return Ok(service);
    }

    /// Get a grant by its key, addressed to anyone
    pub fn get_grant(&self,
                     grant_name: &String)
                     -> Result<Grant, SecretsError> {
        let (service_name, username) = Grant::split_key(grant_name);
        let mut req = SecretsRequest::new(Method::Get, "/api/info");
        req.add_arg("grant", grant_name.clone());

        let mut api_response = try!(self.server_request(req));

        // just make sure the service exists
        try!(api_response.services
            .remove(&service_name)
            .ok_or(SecretsError::ClientError("service not found".to_string())));

        let mut service_block = try!(api_response.grants
            .remove(&service_name)
            .ok_or(SecretsError::ClientError("grant not found".to_string())));
        let grant = try!(service_block.remove(&username)
            .ok_or(SecretsError::ClientError("grant not found".to_string())));

        let grantor = try!(api_response.users
            .remove(&grant.grantor)
            .ok_or(SecretsError::ClientError("user not included".to_string())));

        try!(grant.verify_signature(&grantor.public_sign));

        return Ok(grant);
    }

    /// Get a grant addressed to me, and decrypt it
    pub fn get_decrypted_grant(&self,
                               service_name: &String)
                               -> Result<DecryptedGrant, SecretsError> {
        let username = try!(self.username());

        let mut req = SecretsRequest::new(Method::Get, "/api/info");
        req.add_arg("service", service_name.clone());
        req.add_arg("grant", Grant::key_for(&service_name, &username));

        let mut api_response = try!(self.server_request(req));

        // just make sure the service exists
        try!(api_response.services
            .remove(service_name)
            .ok_or(SecretsError::ClientError("service not found".to_string())));

        let mut service_block = try!(api_response.grants
            .remove(service_name)
            .ok_or(SecretsError::ClientError("grant not found".to_string())));
        let grant = try!(service_block.remove(&username)
            .ok_or(SecretsError::ClientError("grant not found".to_string())));

        let grantor = try!(api_response.users
            .remove(&grant.grantor)
            .ok_or(SecretsError::ClientError("user not included".to_string())));

        let decrypted = try!(self._decrypt_grant(grant, grantor));

        return Ok(decrypted);
    }

    fn _decrypt_grant(&self,
                      grant: Grant,
                      grantor: User)
                      -> Result<DecryptedGrant, SecretsError> {
        let (_, private_key) = try!(self.get_keys());

        // verify_signature may not be necessary. sodiumoxide uses authenticated
        // encryption so while the signature is here to make sure that the
        // grantor is really the one that made this secret, it's possible that
        // the user doesn't really care where the secret came from. the server
        // checks the signature on saving the Grant, so if the server is trusted
        // this is doubly unnecessary. Still, it doesn't hurt
        try!(grant.verify_signature(&grantor.public_sign));

        let plaintext = try!(grant.decrypt(&grantor.public_key, &private_key));
        let decrypted_grant = DecryptedGrant {
            grant: grant,
            plaintext: plaintext,
        };
        return Ok(decrypted_grant);
    }

    pub fn add_grants(&self,
                      service_name: String,
                      grantees: Vec<String>)
                      -> Result<(), SecretsError> {
        let now = UTC::now().timestamp();
        let username = try!(self.username());

        // first pull down the service, our grant, and the public keys of all of
        // our new grantees
        let grant_key = Grant::key_for(&service_name, &username);
        let mut req = SecretsRequest::new(Method::Get, "/api/info");
        req.add_arg("service", service_name.clone());
        req.add_arg("grant", grant_key);
        for ref grantee_name in &grantees {
            req.add_arg("user", (*grantee_name).clone());
        }
        let mut api_response = try!(self.server_request(req));

        let mut service_block = try!(api_response.grants
            .remove(&service_name)
            .ok_or(SecretsError::ClientError("grant not found".to_string())));
        let grant = try!(service_block.remove(&username)
            .ok_or(SecretsError::ClientError("grant not found".to_string())));

        // we didn't ask for this, but the server will automatically add it in
        // because we asked for the grant
        let grantor = try!(api_response.users
                .get(&grant.grantor)
                .ok_or(SecretsError::ClientError("user not included"
                    .to_string())))
            .clone();

        let decrypted_grant = try!(self._decrypt_grant(grant, grantor));

        let grants = try!(self._create_grants(decrypted_grant.plaintext,
                                              &service_name,
                                              now,
                                              grantees,
                                              api_response.users));

        let granter = GrantRequest {
            service_name: service_name,
            grants: grants,
        };

        let mut add_grants_req = SecretsRequest::new(Method::Post,
                                                     "/api/grant");
        try!(add_grants_req.set_json(granter));
        try!(self.server_request(add_grants_req));

        return Ok(());
    }

    pub fn rotate_service(&self,
                          service_name: &String,
                          rotation_strategy: RotationStrategy,
                          plaintext: Vec<u8>)
                          -> Result<(), SecretsError> {
        let now = UTC::now().timestamp();
        let username = try!(self.username());

        let mut req = SecretsRequest::new(Method::Get, "/api/info");
        req.add_arg("service", service_name.clone());
        req.add_arg("grants-for-service", service_name.clone());
        if let RotationStrategy::Only(ref grantees) = rotation_strategy {
            // if we know who we're giving the new secret to, fetch those
            // people. For Copy or Withhold strategies, `grantees` will always
            // cover the new targets so we don't need to name them explicitly
            for grantee in grantees {
                req.add_arg("user", grantee.clone());
            }
        }
        let mut api_response = try!(self.server_request(req));

        // make sure the service exists
        let _: Service = try!(api_response.services
            .remove(service_name)
            .ok_or(SecretsError::ClientError("service not found".to_string())));
        let service_block = try!(api_response.grants
            .remove(service_name)
            .ok_or(SecretsError::ClientError("grants not found".to_string())));

        let current_grants = service_block;

        let mut new_grantee_names: Vec<String> = match rotation_strategy {
            RotationStrategy::Copy => {
                current_grants.keys().map(|s| s.to_owned()).collect()
            }
            RotationStrategy::Only(ref whom) => whom.clone(),
            RotationStrategy::Withhold(ref whom) => {
                current_grants.keys()
                    .filter(|w| !whom.contains(w))
                    .map(|w| w.to_owned())
                    .collect()
            }
        };
        if !new_grantee_names.contains(&username) {
            // the server will insist on this too
            new_grantee_names.push(username.clone());
        }

        let missing_users: Vec<String> = new_grantee_names.iter()
            .filter(|w| !api_response.users.contains_key(*w))
            .map(|w| w.to_owned())
            .collect();
        if missing_users.len() > 0 {
            return Err(SecretsError::UserDoesntExist(missing_users.join(",")));
        }

        let current_grantee_names: Vec<String> = current_grants.keys()
            .map(|w| w.to_owned())
            .collect();
        println!("Previous grantees for {}:\n\t{}",
                 service_name,
                 current_grantee_names.join(","));
        println!("New grantees:\n\t{}", new_grantee_names.join(","));

        if rotation_strategy != RotationStrategy::Copy {
            if !try!(utils::prompt_yn("does that look right? [y/n] ")) {
                return Err(SecretsError::Authentication("refused"));
            }
        }

        let new_grants = try!(self._create_grants(plaintext,
                                                  &service_name,
                                                  now,
                                                  new_grantee_names,
                                                  api_response.users));

        let service_rotator = GrantRequest {
            service_name: service_name.clone(),
            grants: new_grants,
        };

        let mut rotate_req = SecretsRequest::new(Method::Post, "/api/rotate");
        try!(rotate_req.set_json(service_rotator));
        try!(self.server_request(rotate_req));

        return Ok(());
    }

    pub fn all_services(&self) -> Result<Vec<Service>, SecretsError> {
        let mut req = SecretsRequest::new(Method::Get, "/api/info");
        req.add_arg("all-services", "true".to_string());
        let mut api_response = try!(self.server_request(req));
        let services = api_response.services.drain().map(|(_k, v)| v).collect();
        return Ok(services);
    }

    pub fn grants_for_grantee(&self,
                              grantee_name: &String)
                              -> Result<Vec<Grant>, SecretsError> {
        let mut req = SecretsRequest::new(Method::Get, "/api/info");
        req.add_arg("grants-for-grantee", grantee_name.clone());
        let mut api_response = try!(self.server_request(req));

        let mut ret = vec![];

        for (_service_name, mut service_block) in api_response.grants.drain() {
            for (_username, grant) in service_block.drain() {
                ret.push(grant);
            }
        }

        return Ok(ret);
    }

    pub fn grants_for_service(&self,
                              service_name: &String)
                              -> Result<Vec<Grant>, SecretsError> {
        let mut req = SecretsRequest::new(Method::Get, "/api/info");
        req.add_arg("grants-for-service", service_name.clone());
        let mut api_response = try!(self.server_request(req));

        let mut ret = vec![];

        for (_service_name, mut service_block) in api_response.grants.drain() {
            for (_username, grant) in service_block.drain() {
                ret.push(grant);
            }
        }

        return Ok(ret);
    }
}

fn http_path(host_str: &str, postfix: &str) -> String {
    let mut ret = String::new();
    ret.push_str("https://");
    ret.push_str(host_str);
    ret.push_str(postfix);
    ret
}

#[derive(Debug)]
pub struct DecryptedGrant {
    pub grant: Grant,
    pub plaintext: Vec<u8>,
}

struct SecretsRequest {
    method: Method,
    path: &'static str,
    arguments: Vec<(&'static str, String)>,
    json: Option<Vec<u8>>,
}

// when we are rotating a password, to whom do we give it?
#[derive(Debug, PartialEq)]
pub enum RotationStrategy {
    Copy, // everyone that has it now
    Only(Vec<String>), // only these people plus the grantor)
    Withhold(Vec<String>), // everyone except these people
}

impl SecretsRequest {
    fn new(method: Method, path: &'static str) -> Self {
        SecretsRequest {
            method: method,
            path: path,
            arguments: Vec::new(),
            json: None,
        }
    }

    fn add_arg(&mut self, name: &'static str, value: String) -> &mut Self {
        self.arguments.push((name, value));
        return self;
    }

    fn set_json<T: Serialize>(&mut self, value: T) -> Result<(), SecretsError> {
        debug_assert!(self.json.is_none());
        let serialized = try!(json_to_vec(&value));
        self.json = Some(serialized);
        return Ok(());
    }
}

fn verify_ssl_fingerprint(_preverify_ok: bool,
                          x509_ctx: &X509StoreContext,
                          expected_values: &(String, String))
                          -> bool {
    let (ref expected_fingerprint, ref expected_cn) = *expected_values;

    let pem = x509_ctx.get_current_cert();
    if pem.is_none() {
        error!("remote provided no cert");
        return false;
    }
    let pem = pem.unwrap();

    let remote_fingerprint = pem.fingerprint(HashType::SHA256);
    if remote_fingerprint.is_none() {
        error!("remote had no fingerprint");
        return false;
    }
    let remote_fingerprint = remote_fingerprint.unwrap().to_hex();

    let cn = pem.subject_name().text_by_nid(Nid::CN);
    if cn.is_none() {
        error!("remote has no common name");
        return false;
    }
    let cn = (*cn.unwrap()).to_owned();

    let cn_matches = utils::constant_time_compare(&cn.as_bytes(),
                                                  &expected_cn.as_bytes());
    let fingerprint_matches =
        utils::constant_time_compare(&remote_fingerprint.as_bytes(),
                                     &expected_fingerprint.as_bytes());
    return cn_matches && fingerprint_matches;
}

impl SecretsContainer for SecretsClient {
    fn get_db(&self) -> &rusqlite::Connection {
        return &self.db;
    }

    fn get_password(&self) -> &String {
        return &self.password;
    }
}

fn create_client_schema(_conn: &mut rusqlite::Connection)
                        -> Result<(), rusqlite::Error> {
    Ok(())
}
