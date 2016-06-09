use std::path::Path;
use std::rc::Rc;
use std::cell::RefCell;
use std::sync::Arc;

use hyper;
use hyper::client::IntoUrl;
use hyper::net::OpensslClient;
use hyper::net::HttpsConnector;
use openssl::ssl::error::SslError;
use openssl::ssl::SslVerifyMode;
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::ssl::SSL_VERIFY_NONE;
use openssl::x509::X509StoreContext;
use hyper::net::Openssl;
use rusqlite;
use serde_json;
use term;

use keys;

quick_error! {
    #[derive(Debug)]
    pub enum ClientError {
        RusqliteError(err: rusqlite::Error) { from() }
        HyperError(err: hyper::Error) { from() }
        SslError(err: SslError) { from() }
        ServerError(err: String) { }
        JustBecause(err: &'static str) {  }
    }
}

pub struct SecretsClient {
    db_conn: rusqlite::Connection,
    http_client: hyper::Client,
}

impl SecretsClient {
    pub fn create<P: AsRef<Path>>(path: P, host: String,
                                  username: String, password: String,
                              ) -> Result<Self, ClientError> {
        let (public_key, private_key) = keys::create_key();

        // let http = hyper::Client::new();

        // set up the SSL verifier to prompt them for the fingerprint
        let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1));
        let verifier = SslVerifyRecorder::new();
        ssl_context.set_verify_with_data(
            SSL_VERIFY_NONE,
            SslVerifyRecorder::verify,
            verifier);
        let ssl = Openssl {context: Arc::new(ssl_context)};
        let connector = HttpsConnector::new(ssl);
        let http = hyper::Client::with_connector(connector);

        try!(Self::check_health(&http, &host));

        Err(ClientError::JustBecause("I said so"))
        // return Ok(SecretsClient {})
    }

    fn check_health(http: &hyper::Client, host: &String) -> Result<(), ClientError> {
        let response = try!(http.get(&path(&host, "/api/health")).send());
        if response.status == hyper::Ok {
            Ok(())
        } else {
            Err(ClientError::ServerError(format!("unknown status {:?}", response.status)))
        }
    }

    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self, ClientError> {
        return Err(ClientError::JustBecause("I said so"))
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

struct SslVerifyRecorder {
    fingerprint: RefCell<Option<String>>
}

impl SslVerifyRecorder {
    pub fn new() -> Self {
        return SslVerifyRecorder { fingerprint: RefCell::new(None) }
    }

    pub fn verify(preverify_ok: bool, _x509_ctx: &X509StoreContext, data: &Self) -> bool {
        println!("verifying SSL! {}", preverify_ok);
        *data.fingerprint.borrow_mut() = Some("got it!".to_string());
        // data.fingerprint.set(Some("got it!".to_string()));
        return true;
    }
}
