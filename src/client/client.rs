use std::io;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use hyper;
use hyper::net::HttpsConnector;
use hyper::status::StatusCode;
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::ssl::{SSL_VERIFY_NONE, SSL_VERIFY_PEER, SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3, SSL_OP_NO_COMPRESSION};
use openssl::x509::X509StoreContext;
use openssl::crypto::hash::Type as HashType;
use openssl::nid::Nid;
use hyper::net::Openssl;
use rusqlite;
use serde_json::builder::ObjectBuilder;
use serde_json::ser::to_string as json_to_string;
use serde_json::from_reader as json_from_reader;
use serde_json::Value as JsonValue;
use rustc_serialize::base64::ToBase64;
use rustc_serialize::base64::STANDARD as STANDARD_BASE64_CONFIG;

use utils;
use common;
use common::SecretsError;
use common::SecretsContainer;

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
        // fingerprint we conencted to is the same. That's okay because all
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
        let info_url = http_path(&host, "/api/info");
        info!("connecting to {}", info_url);
        let response = try!(http.get(&info_url).send());
        if response.status != hyper::Ok {
            return Err(SecretsError::ServerError(format!("unknown status {}", response.status)))
        }
        let got_json: JsonValue = try!(json_from_reader(response));

        let server_fingerprint = try!(common::json_get_string(&got_json, "server_fingerprint"));
        let server_cn = try!(common::json_get_string(&got_json, "server_cn"));
        let server_public_sign = try!(common::json_get_string(&got_json, "server_public_sign"));
        let server_public_key = try!(common::json_get_string(&got_json, "server_public_key"));

        try!(io::stderr().write("connected to server\n".as_bytes()));
        try!(io::stderr().write(format!("server fingerprint: {}\n", server_fingerprint).as_bytes()));
        try!(io::stderr().write(format!("server cn: {}\n", server_cn).as_bytes()));
        try!(io::stderr().write(format!("server public_key: {}\n", server_public_key).as_bytes()));
        try!(io::stderr().write(format!("server public_sign: {}\n", server_public_sign).as_bytes()));

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
        try!(client.set_global("server_fingerprint", &server_fingerprint));
        try!(client.set_global("server_cn", &server_cn));
        try!(client.set_global("server_public_key", &server_public_key));
        try!(client.set_global("server_public_sign", &server_public_sign));

        return Ok(client);
    }

    pub fn generate_join_request(&mut self) -> Result<String, SecretsError> {
        info!("creating join request");

        let server_fingerprint = try!(self.get_global::<String>("server_fingerprint"));
        let server_cn = try!(self.get_global::<String>("server_cn"));
        let server_public_key = try!(self.get_global::<String>("server_public_key"));
        let server_public_sign = try!(self.get_global::<String>("server_public_sign"));

        let username = try!(self.username());
        let client_fingerprint = try!(self.ssl_fingerprint());
        let client_public_key = try!(self.get_global::<Vec<u8>>("public_key"));
        let client_public_sign = try!(self.get_global::<Vec<u8>>("public_sign"));

        let requester_value = ObjectBuilder::new()
            .insert("server_fingerprint", server_fingerprint)
            .insert("server_cn", server_cn)
            .insert("server_public_key", server_public_key)
            .insert("server_public_sign", server_public_sign)
            .insert("client_username", username)
            .insert("client_fingerprint", client_fingerprint)
            .insert("client_public_key", utils::hex(&client_public_key))
            .insert("client_public_sign", utils::hex(&client_public_sign))
            .unwrap();
        let js = try!(json_to_string(&requester_value));
        let b64 = js.as_bytes().to_base64(STANDARD_BASE64_CONFIG);
        return Ok(b64);
    }

    pub fn check_server(&self) -> Result<(), SecretsError> {
        let json_response = try!(self.server_get("/api/auth"));
        try!(common::json_get_string(&json_response, "healthy"));
        return Ok(());
    }

    fn server_get(&self, endpoint: &str) -> Result<JsonValue, SecretsError> {
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
        let url = http_path(&host, endpoint);
        debug!("connecting to {}", url);
        let response = try!(http_client.get(&url).send());
        if response.status != StatusCode::Ok {
            return Err(SecretsError::ServerError(format!(
                "got an error from the server: {}",
                response.status)));
        }
        let json_response: JsonValue = try!(json_from_reader(response));
        if !json_response.is_object() {
            return Err(SecretsError::ServerResponseError("got a non-object from the server".to_string()));
        }
        return Ok(json_response);
    }

    pub fn connect<P: AsRef<Path>>(config_file: P, password: String) -> Result<Self, SecretsError> {
        let db = try!(common::connect_db(config_file));
        let mut client = SecretsClient {
            db: db,
            password: password,
        };
        try!(client.check_db());
        try!(client.get_keys()); // make sure this effectively checks their password
        return Ok(client);
    }

    fn username(&mut self) -> Result<String, SecretsError> {
        let username = try!(self.get_global::<String>("username"));
        return Ok(username);
    }
}

fn http_path(host_str: &String, postfix: &str) -> String {
    let mut ret = String::new();
    ret.push_str("https://");
    ret.push_str(&host_str);
    ret.push_str(postfix);
    ret
}

/// SSL verifier callback function that accepts any certificate, but records the
/// cn/fingerprint
pub fn verify_fingerprint(_preverify_ok: bool, x509_ctx: &X509StoreContext, expected_values: &(String, String)) -> bool {
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
    let remote_fingerprint = remote_fingerprint.unwrap();
    let remote_fingerprint = utils::hex(&remote_fingerprint);

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
