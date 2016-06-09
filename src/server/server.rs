use std::path::Path;
use std::sync::Mutex;
use std::sync::Arc;

use log;
use rusqlite;
use hyper::server::{Handler, Server, Request, Response};
use hyper::method::Method;
use hyper::status::StatusCode;
use hyper::uri::RequestUri;
use hyper::net::Openssl;
use hyper::net::Ssl as HyperSsl;
use hyper::Error as HyperError;
use openssl::x509::X509FileType;
use openssl::ssl::Ssl;
use openssl::ssl::error::SslError as OpenSslError;
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;

use server::server_db::ServerDb;

quick_error! {
    #[derive(Debug)]
    pub enum ServerError {
        SslError(err: OpenSslError) { from() }
        HyperError(err: HyperError) { from() }
    }
}

struct ServerHandler {
    db_conn: Mutex<ServerDb>
}

impl ServerHandler {
    fn check_db(&self) -> Result<(), rusqlite::Error> {
        self.db_conn.lock().unwrap().check_db()
    }
}

impl Handler for ServerHandler {
    fn handle(&self, request: Request, mut response: Response) {
        if url_matches(request, Method::Get, "/api/health") {
            let healthy = self.check_db();
            if healthy.is_ok() {
                response.send(b"good!").unwrap();
                return;
            } else {
                error!("unhealhy: {:?}", healthy);
                *response.status_mut() = StatusCode::InternalServerError;
                return;
            }
        } else {
            *response.status_mut() = StatusCode::NotFound;
        }

        //
        // }
        // let uri = match request.uri {
        //     AbsolutePath(x) => x,
        //     =
        // }
        //
        // match request.uri {
        //     x if x.starts_with("/api/health") => {
        //         response.write("good!")
        //     }
        // }
        // self.sender.lock().unwrap().send("start").unwrap();
    }
}

pub fn start_server<P: AsRef<Path>>(db_conn: ServerDb,
                                    ssl_key_path: P, ssl_cert_path: P,
                                    listen: &str) -> Result<(), ServerError> {
    let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1));
    try!(ssl_context.set_private_key_file(ssl_key_path, X509FileType::PEM));
    try!(ssl_context.set_certificate_file(ssl_cert_path, X509FileType::PEM));
    let ssl = Openssl {context: Arc::new(ssl_context)};
    let server = try!(Server::https(listen, ssl));
    let mutexed_db_conn = Mutex::new(db_conn);
    try!(server.handle(ServerHandler {db_conn: mutexed_db_conn}));
    Ok(())
}

use openssl::x509::X509Generator;
use openssl::ssl::error::SslError;
use openssl::crypto::hash::Type;
use openssl::x509::extension::Extension::KeyUsage;
use openssl::x509::extension::KeyUsageOption::DigitalSignature;

pub fn init_ssl_cert(cn: String) -> Result<(Vec<u8>, Vec<u8>), SslError> {
    let gen = X509Generator::new()
        .set_bitlength(4096)
        .set_valid_period(365*5) // TODO need a way to renew this then
        .add_name("CN".to_string(), cn)
        .set_sign_hash(Type::SHA256)
        .add_extension(KeyUsage(vec![DigitalSignature])); // so that we can sign client certs

    let (x509_cert, pkey) = try!(gen.generate());

    let mut x509_cert_blob = Vec::new();
    x509_cert.write_pem(&mut x509_cert_blob);

    let mut pkey_blob = Vec::new();
    pkey.write_pem(&mut pkey_blob);

    return Ok((x509_cert_blob, pkey_blob))
}

fn url_matches(request: Request, method: Method, prefix: &str) -> bool {
    match request.uri {
        RequestUri::AbsolutePath(ref x) if x.starts_with(prefix)
                                    && request.method == method
                                    => {
            true
        }
        _ => false
    }
}
