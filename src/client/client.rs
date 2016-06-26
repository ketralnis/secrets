use std::io;
use std::io::Write;
use std::path::Path;
use std::cell::RefCell;
use std::sync::Arc;
use std::rc::Rc;

use hyper;
use hyper::net::HttpsConnector;
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::ssl::SSL_VERIFY_PEER;
use openssl::x509::X509StoreContext;
use openssl::crypto::hash::Type as HashType;
use openssl::nid::Nid;
use hyper::net::Openssl;
use rusqlite;
use serde_json::builder::ObjectBuilder;
use serde_json::ser::to_string;

use utils;
use common;
use common::SecretsError;
use common::SecretsContainer;

pub struct SecretsClient {
    db: rusqlite::Connection,
    password: String,
}

impl SecretsClient {
    pub fn create<P: AsRef<Path>>(config_file: P, host: String,
                                  username: String, password: String,
                              ) -> Result<Self, SecretsError> {

        // this creates a new local database and connects to the server to get
        // its fingerprint. Because we aren't really set up yet, we have to do a
        // lot by hand that the normal client can just do through convenience
        // methods

        // set up the SSL verifier to prompt them for the fingerprint
        let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1));
        let recorder: Rc<RefCell<Option<(String, String)>>> = Rc::new(RefCell::new(Option::None));
        ssl_context.set_verify_with_data(
            SSL_VERIFY_PEER,
            verify_record,
            recorder.clone());
        let ssl = Openssl {context: Arc::new(ssl_context)};
        let connector = HttpsConnector::new(ssl);
        let http = hyper::Client::with_connector(connector);

        // this will connect via that configured SSL client which will record
        // the server's fingerprint and CN into the recorder
        info!("connecting to {}", host);
        try!(Self::check_server_health(&http, &host));

        // unpack the recorder
        let ref fingerprint = *recorder.borrow();
        let (cn, fingerprint) = match fingerprint {
            &None => {
                return Err(SecretsError::Unknown("couldn't extract fingerprint?"));
            },
            &Some((ref cn, ref fingerprint)) => {
                (cn.clone(), fingerprint.clone())
            }
        };

        try!(io::stderr().write("connected to server\n".as_bytes()));
        try!(io::stderr().write(format!("cn: {}\n", cn).as_bytes()));
        try!(io::stderr().write(format!("fingerprint: {}\n", fingerprint).as_bytes()));

        let confirmed = try!(utils::prompt_yn("does that look right? [y/n] "));
        if !confirmed {
            return Err(SecretsError::Unknown("refused cn/fingerprint"));
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
        try!(client.set_global("server_fingerprint", &fingerprint));
        try!(client.set_global("server_cn", &cn));

        return Ok(client);
    }

    pub fn generate_join_request(&mut self) -> Result<String, SecretsError> {
        info!("creating join request");

        let server_fingerprint = try!(self.get_global::<String>("server_fingerprint"));
        let server_cn = try!(self.get_global::<String>("server_cn"));
        let username = try!(self.username());
        let client_fingerprint = try!(self.ssl_fingerprint());
        let client_public_key = try!(self.get_global::<Vec<u8>>("public_key"));
        let client_public_sign = try!(self.get_global::<Vec<u8>>("public_sign"));

        let requester_value = ObjectBuilder::new()
            .insert("server_fingerprint", server_fingerprint)
            .insert("server_common_name", server_cn)
            .insert("client_username", username)
            .insert("client_fingerprint", client_fingerprint)
            .insert("client_public_key", utils::hex(&client_public_key))
            .insert("client_public_sign", utils::hex(&client_public_sign))
            .unwrap();
        // let key_sig =
        let js = try!(to_string(&requester_value));
        return Ok(js);
    }

    // fn key_sig(value: serde_json::Value) {
    //
    // }

    fn check_server_health(http: &hyper::Client, host: &String) -> Result<(), SecretsError> {
        let response = try!(http.get(&path(&host, "/api/health")).send());
        if response.status == hyper::Ok {
            Ok(())
        } else {
            Err(SecretsError::ServerError(format!("unknown status {:?}", response.status).to_owned()))
        }
    }

    fn server_get(&mut self, endpoint: &str) -> Result<(), SecretsError> {
        // set up the SSL verifier to check the fingerprint
        let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1));
        let server_fingerprint = try!(self.get_global::<String>("server_fingerprint"));
        ssl_context.set_verify_with_data(
            SSL_VERIFY_PEER,
            verify_fingerprint,
            server_fingerprint);
        let ssl = Openssl {context: Arc::new(ssl_context)};
        let connector = HttpsConnector::new(ssl);
        let http = hyper::Client::with_connector(connector);

        let host = try!(self.get_global::<String>("server_host"));
        let url = format!("{}/{}", host, endpoint);
        let http_client = hyper::Client::new();
        let response = http_client.get(&url);

        return Ok(());
    }

    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self, SecretsError> {
        return Err(SecretsError::NotImplemented("I said so"))
        // return Ok(SecretsClient {})
    }

    fn username(&mut self) -> Result<String, SecretsError> {
        let username = try!(self.get_global::<String>("username"));
        return Ok(username);
    }
}

fn path(host_str: &String, postfix: &str) -> String {
    let mut ret = String::new();
    ret.push_str("https://");
    ret.push_str(&host_str);
    ret.push_str(postfix);
    ret
}

/// SSL verifier callback function that accepts any certificate, but records the
/// cn/fingerprint
pub fn verify_record(_preverify_ok: bool, x509_ctx: &X509StoreContext, data: &Rc<RefCell<Option<(String,String)>>>) -> bool {
    let pem = x509_ctx.get_current_cert();
    if pem.is_none() {
        error!("remote provided no cert");
        return false;
    }
    let pem = pem.unwrap();

    let fingerprint = pem.fingerprint(HashType::SHA256);
    if fingerprint.is_none() {
        error!("remote had no fingerprint");
        return false
    }
    let fingerprint = fingerprint.unwrap();
    let fingerprint = utils::hex(&fingerprint);

    let cn = pem.subject_name().text_by_nid(Nid::CN);
    if cn.is_none() {
        error!("remote has no common name");
        return false;
    }
    let cn = (*cn.unwrap()).to_owned();

    if let Some((ref old_cn, ref old_fingerprint)) = *data.borrow() {
        // openssl calls us twice for some reason but it's fine as long as
        // it's the same fingerprint both times

        if old_cn[..] == cn[..] && old_fingerprint[..] == fingerprint[..] {
            return true;
        } else {
            error!("conflicting cn/fingerprints {}/{} != {}/{}",
                   old_cn, old_fingerprint,
                   cn, fingerprint);
            return false;
        }
    }
    *data.borrow_mut() = Some((cn, fingerprint));
    return true;
}

/// SSL verifier callback function that accepts any certificate, but records the
/// cn/fingerprint
pub fn verify_fingerprint(_preverify_ok: bool, x509_ctx: &X509StoreContext, expected_fingerprint: &String) -> bool {
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

    return utils::constant_time_compare(&remote_fingerprint.as_bytes(),
                                        &expected_fingerprint.as_bytes());
}


impl SecretsContainer for SecretsClient {
    fn get_db(&mut self) -> &mut rusqlite::Connection {
        return &mut self.db;
    }

    fn get_password(&self) -> &String {
        return &self.password;
    }
}

fn create_client_schema(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    Ok(())
}
