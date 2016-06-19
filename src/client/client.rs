use std::io;
use std::io::Write;
use std::path::Path;
use std::cell::RefCell;
use std::sync::Arc;
use std::rc::Rc;

use hyper;
use hyper::net::OpensslClient;
use hyper::net::HttpsConnector;
use openssl::ssl::error::SslError;
use openssl::ssl::SslVerifyMode;
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::ssl::SSL_VERIFY_PEER;
use openssl::x509::X509StoreContext;
use openssl::crypto::hash::Type as HashType;
use openssl::nid::Nid;
use hyper::net::Openssl;
use rusqlite;
use serde_json;

use keys;
use utils;
use common::SecretsError;

pub struct SecretsClient {
    db_conn: rusqlite::Connection,
    http_client: hyper::Client,
}

impl SecretsClient {
    pub fn create<P: AsRef<Path>>(path: P, host: String,
                                  username: String, password: String,
                              ) -> Result<Self, SecretsError> {
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
        try!(Self::check_health(&http, &host));

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
        let (public_key, private_key) = keys::create_keypair();


        try!(io::stderr().write("send this to your local friendly secrets admin:".as_bytes()));

        println!("got fingerprint {}", fingerprint);

        Err(SecretsError::NotImplemented("I said so"))
        // return Ok(SecretsClient {})
    }

    fn check_health(http: &hyper::Client, host: &String) -> Result<(), SecretsError> {
        let response = try!(http.get(&path(&host, "/api/health")).send());
        if response.status == hyper::Ok {
            Ok(())
        } else {
            Err(SecretsError::ServerError(format!("unknown status {:?}", response.status).to_owned()))
        }
    }

    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self, SecretsError> {
        return Err(SecretsError::NotImplemented("I said so"))
        // return Ok(SecretsClient {})
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
    let fingerprint = utils::hex(fingerprint);

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
