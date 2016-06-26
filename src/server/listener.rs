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
use serde_json::builder::ObjectBuilder;
use serde_json::ser::to_string;

use utils;
use server::server::SecretsServer;
use common::SecretsError;
use common::SecretsContainer;

struct ServerHandler {
    instance: Arc<Mutex<SecretsServer>>
}

impl ServerHandler {
    fn check_db(&self) -> Result<ObjectBuilder, SecretsError> {
        let mut instance = self.instance.lock().unwrap();
        try!(instance.check_db());
        let builder = ObjectBuilder::new()
            .insert("healthy", true);
        return Ok(builder);
    }

    fn server_info(&self) -> Result<ObjectBuilder, SecretsError> {
        let mut instance = self.instance.lock().unwrap();
        let server_fingerprint = try!(instance.ssl_fingerprint());
        let (public_key, _) = try!(instance.get_keys());
        let (public_sign, _) = try!(instance.get_signs());

        let builder = ObjectBuilder::new()
            .insert("server_fingerprint", server_fingerprint)
            .insert("server_public_key", utils::hex(&public_key.as_ref()))
            .insert("server_public_sign", utils::hex(&public_sign.as_ref()));
        return Ok(builder);
    }

    fn return_json(&self,
                   maybe_builder: Result<ObjectBuilder, SecretsError>,
                   mut response: Response) -> () {
        match maybe_builder {
            Result::Ok(builder) => {
                let value = builder.unwrap(); // not a panicking unwrap

                match to_string(&value) {
                    Result::Ok(value_str) => {
                        *response.status_mut() = StatusCode::Ok;
                        response.send(value_str.as_bytes()).unwrap();
                    },
                    Result::Err(error) => {
                        error!("Error encoding JSON: {:?}", error);
                        *response.status_mut() = StatusCode::InternalServerError;
                    }
                }
            },
            Result::Err(error) => {
                error!("Error in request: {:?}", error);
                *response.status_mut() = StatusCode::InternalServerError;
            }
        }
    }

    fn return_error(&self, err_str: &str, mut response: Response, status_code: StatusCode) {
        *response.status_mut() = status_code;
        let value = ObjectBuilder::new()
            .insert("error", err_str)
            .unwrap();
        response.send(to_string(&value).unwrap().as_bytes()).unwrap();
    }
}

impl Handler for ServerHandler {
    fn handle(&self, request: Request, mut response: Response) -> () {
        if url_matches(&request, Method::Get, "/api/health") {
            let healthy = self.check_db();
            return self.return_json(
                healthy,
                response);

        } else if url_matches(&request, Method::Get, "/api/info") {
            let server_info = self.server_info();
            return self.return_json(server_info,
                                    response);

        } else {
            return self.return_error(
                "unknown URL",
                response,
                StatusCode::NotFound);
        }
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
    info!("terminating");
    Ok(())
}

fn url_matches(request: &Request, method: Method, prefix: &str) -> bool {
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
