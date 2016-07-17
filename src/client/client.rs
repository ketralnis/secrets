use std::io;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use hyper;
use hyper::method::Method;
use hyper::net::HttpsConnector;
use hyper::net::Openssl;
use hyper::status::StatusCode;
use hyper::Url;
use openssl::crypto::hash::Type as HashType;
use openssl::nid::Nid;
use openssl::ssl::{SSL_VERIFY_NONE, SSL_VERIFY_PEER, SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3, SSL_OP_NO_COMPRESSION};
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::x509::X509StoreContext;
use rusqlite;
use rustc_serialize::hex::ToHex;
use serde_json::from_reader as dejson_from_reader;
use serde_json::ser::to_string as json_to_string;
use serde_json::Value as JsonValue;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use url::form_urlencoded::Serializer as QueryStringSerializer;

use api::{ApiResponse, PeerInfo, JoinRequest};
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
    pub fn create<P: AsRef<Path>>(config_file: P, host: String,
                                  username: String, password: String,
                              ) -> Result<Self, SecretsError> {
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
        ssl_context.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);
        try!(ssl_context.set_cipher_list("ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4@STRENGTH"));
        let ssl = Openssl {context: Arc::new(ssl_context)};
        let connector = HttpsConnector::new(ssl);
        let http = hyper::Client::with_connector(connector);

        // this will connect via that configured SSL client which will record
        // the server's fingerprint and CN into the recorder
        let info_url = http_path(&host, "/api/server");
        info!("connecting to {}", info_url);
        let response = try!(http.get(&info_url).send());
        if response.status != hyper::Ok {
            return Err(SecretsError::ClientError(format!("unknown status {}", response.status)))
        }

        let api_response: ApiResponse = try!(dejson_from_reader(response));
        let server_info = try!(api_response.server_info.ok_or(
            SecretsError::ClientError("missing server info".to_string())));

        try!(io::stderr().write(format!("=== server info: ===\n{}\n",
                                        try!(server_info.printable_report()))
                                    .as_bytes()));

        let confirmed = try!(utils::prompt_yn("does that look right? [y/n] "));
        if !confirmed {
            return Err(SecretsError::Authentication("refused server credentials"));
        }

        info!("creating client DB");

        let mut db = try!(common::create_db(config_file));
        try!(create_client_schema(&mut db));

        let mut client = SecretsClient {
            db: db,
            password: password
        };

        try!(client.create_and_store_keys(&username));
        try!(client.set_global("username", &username));
        try!(client.set_global("server_host", &host));
        try!(client.set_global("server_fingerprint", &server_info.fingerprint));
        try!(client.set_global("server_cn", &server_info.cn));
        try!(client.set_global("server_public_key", &server_info.public_key.as_ref()));
        try!(client.set_global("server_public_sign", &server_info.public_sign.as_ref()));

        return Ok(client);
    }

    pub fn join_request(&self) -> Result<JoinRequest, SecretsError> {
        info!("creating join request");

        let server_info = try!(self.get_server_info());
        let client_info = try!(self.get_peer_info());
        let join_request = JoinRequest {
            server_info: server_info,
            client_info: client_info
        };
        return Ok(join_request);
    }

    pub fn get_server_info(&self) -> Result<PeerInfo, SecretsError> {
        let cn = try!(self.get_global::<String>("server_cn"));
        let fingerprint = try!(self.get_global::<String>("server_fingerprint"));

        let public_key_vec: Vec<u8> = try!(self.get_global("server_public_key"));
        let public_key = box_::PublicKey::from_slice(&public_key_vec);
        let public_key = try!(public_key.ok_or(keys::CryptoError::Unknown));

        let public_sign_vec: Vec<u8> = try!(self.get_global("server_public_sign"));
        let public_sign = sign::PublicKey::from_slice(&public_sign_vec);
        let public_sign = try!(public_sign.ok_or(keys::CryptoError::Unknown));

        return Ok(PeerInfo {
            cn: cn, fingerprint: fingerprint,
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
        if !api_response.users.iter().any(|(_, user)| *user.username == username) {
            return Err(SecretsError::ClientError("how come I'm not in here?".to_string()));
        }
        return Ok(());
    }

    fn server_request(&self, req: SecretsRequest) -> Result<ApiResponse, SecretsError> {
        // set up the SSL verifier to check the fingerprint
        let (public_pem, private_pem) = try!(self.get_pems());
        let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1));
        ssl_context.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);
        try!(ssl_context.set_cipher_list("ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4@STRENGTH"));
        try!(ssl_context.set_certificate(&public_pem));
        try!(ssl_context.set_private_key(&private_pem));
        try!(ssl_context.check_private_key());

        let server_fingerprint = try!(self.get_global::<String>("server_fingerprint"));
        let server_cn = try!(self.get_global::<String>("server_cn"));
        ssl_context.set_verify_with_data(
            SSL_VERIFY_PEER,
            verify_fingerprint,
            (server_fingerprint, server_cn));

        let ssl = Openssl {context: Arc::new(ssl_context)};
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
            },
            (Method::Post, None) => {
                http_client.post(url).send()
            }
            (Method::Post, Some(json_value)) => {
                let json_str = try!(json_to_string(&json_value));
                http_client.post(url)
                    .body(json_str.as_bytes())
                    .send()
            },
            _ => unreachable!()
        });

        if response.status != StatusCode::Ok {
            return Err(SecretsError::ClientError(format!(
                "got an error from the server ({}): {}",
                req.path, response.status)));
        }
        let api_response: ApiResponse = try!(dejson_from_reader(response));
        if let Some(err) = api_response.error {
            return Err(SecretsError::ClientError(err));
        }
        return Ok(api_response);
    }

    pub fn connect<P: AsRef<Path>>(config_file: P, password: String) -> Result<Self, SecretsError> {
        let db = try!(common::connect_db(config_file));
        let client = SecretsClient {
            db: db,
            password: password,
        };
        try!(client.check_db());
        try!(client.get_keys()); // make sure this effectively checks their password
        return Ok(client);
    }

    pub fn username(&self) -> Result<String, SecretsError> {
        let username = try!(self.get_global::<String>("username"));
        return Ok(username);
    }

    pub fn create_service(&mut self,
                          service_name: String,
                          plaintext: String,
                          grantees: Vec<String>)
                          -> Result<(), SecretsError> {
        // look up the users that we'll grant to
        let mut req = SecretsRequest::new(Method::Get, "/api/users");
        for grantee in grantees {
            req.add_arg("user", grantee);
        }
        let json = try!(self.server_request(req));
        println!("{}", "json");
        unreachable!();
        Ok(())
    }
}

fn http_path(host_str: &str, postfix: &str) -> String {
    let mut ret = String::new();
    ret.push_str("https://");
    ret.push_str(host_str);
    ret.push_str(postfix);
    ret
}

struct SecretsRequest {
    method: Method,
    path: &'static str,
    arguments: Vec<(&'static str, String)>,
    json: Option<JsonValue>,
}

impl SecretsRequest {
    fn new(method: Method, path: &'static str) -> Self {
        SecretsRequest {
            method: method,
            path: path,
            arguments: Vec::new(),
            json: None
        }
    }

    fn add_arg(&mut self, name: &'static str, value: String) -> &mut Self {
        self.arguments.push((name, value));
        return self;
    }

    fn set_json(&mut self, value: JsonValue) -> &mut Self {
        self.json = Some(value);
        return self;
    }
}

pub fn verify_fingerprint(_preverify_ok: bool,
                          x509_ctx: &X509StoreContext,
                          expected_values: &(String, String)) -> bool {
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
        return false
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
    let fingerprint_matches = utils::constant_time_compare(&remote_fingerprint.as_bytes(),
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

fn create_client_schema(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    Ok(())
}
