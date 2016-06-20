use std::sync::Mutex;
use std::sync::Arc;

use hyper::server::{Handler, Request, Response};
use hyper::server::Server as HyperServer;
use hyper::method::Method;
use hyper::status::StatusCode;
use hyper::uri::RequestUri;
use hyper::net::Openssl;
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;

use server::server::SecretsServer;
use common::SecretsError;
use common::SecretsContainer;

struct ServerHandler {
    instance: Arc<Mutex<SecretsServer>>
}

impl ServerHandler {
    fn check_db(&self) -> Result<(), SecretsError> {
        self.instance.lock().unwrap().check_db()
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

fn make_ssl(instance: &mut SecretsServer) -> Result<Openssl, SecretsError> {
    let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1));
    let (public_pem, private_pem) = try!(instance.get_pems());
    try!(ssl_context.set_certificate(&public_pem));
    try!(ssl_context.set_private_key(&private_pem));
    let ssl = Openssl {context: Arc::new(ssl_context)};
    return Ok(ssl);
}

pub fn listen(mut instance: SecretsServer, listen: &str) -> Result<(), SecretsError> {
    let ssl = try!(make_ssl(&mut instance));
    let hyper_server = try!(HyperServer::https(listen, ssl));
    let mutexed_instance = Arc::new(Mutex::new(instance));
    let server_handler = ServerHandler {instance: mutexed_instance};
    try!(hyper_server.handle(server_handler));
    Ok(())
}

fn url_matches(request: Request, method: Method, prefix: &str) -> bool {
    match request.uri {
        RequestUri::AbsolutePath(ref x)
                if x.starts_with(prefix)
                && request.method == method
                => {
            true
        }
        _ => false
    }
}
