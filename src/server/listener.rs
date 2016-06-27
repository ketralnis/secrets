use std::sync::Mutex;
use std::sync::Arc;

use hyper::server::{Handler, Request, Response};
use hyper::server::Server as HyperServer;
use hyper::method::Method;
use hyper::status::StatusCode;
use hyper::uri::RequestUri;
use hyper::net::Openssl;
use hyper::net::HttpStream;
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::ssl::SslStream;
use openssl::ssl::{SSL_VERIFY_NONE, SSL_VERIFY_PEER, SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3, SSL_OP_NO_COMPRESSION};
use openssl::x509::X509StoreContext;
use openssl::crypto::hash::Type as HashType;
use openssl::nid::Nid;
use serde_json::builder::ObjectBuilder;
use serde_json::ser::to_string;

use utils;
use server::server::SecretsServer;
use server::server::User;
use common::SecretsError;
use common::SecretsContainer;

struct ServerHandler {
    instance: Arc<Mutex<SecretsServer>>
}

impl ServerHandler {
    fn check_db(&self, instance: &SecretsServer) -> Result<ObjectBuilder, SecretsError> {
        try!(instance.check_db());
        let builder = ObjectBuilder::new()
            .insert("healthy", "yes");
        return Ok(builder);
    }

    fn server_info(&self, instance: &SecretsServer) -> Result<ObjectBuilder, SecretsError> {
        let server_cn = try!(instance.ssl_cn());
        let server_fingerprint = try!(instance.ssl_fingerprint());
        let (public_key, _) = try!(instance.get_keys());
        let (public_sign, _) = try!(instance.get_signs());

        let builder = ObjectBuilder::new()
            .insert("server_cn", server_cn)
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
                        response.start().unwrap().end().unwrap();
                    }
                }
            },
            Result::Err(error) => {
                error!("Error in request: {:?}", error);
                *response.status_mut() = StatusCode::InternalServerError;
                response.start().unwrap().end().unwrap();
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
    fn handle(&self, request: Request, response: Response) -> () {
        let ref instance = *self.instance.lock().unwrap();

        if url_matches(&request, Method::Get, "/api/health") {
            let healthy = self.check_db(instance);
            return self.return_json(
                healthy,
                response);

        } else if url_matches(&request, Method::Get, "/api/info") {
            let server_info = self.server_info(&instance);
            return self.return_json(server_info,
                                    response);
        }

        // all other requests require a client cert
        let user = match authenticate_request(&instance, &request) {
            Ok(user) => user,
            Err(SecretsError::Authentication(s)) => {
                return self.return_error(s,
                                         response,
                                         StatusCode::Unauthorized);
            }
            Err(err) => {
                error!("error authenticating {:?}", err);
                return self.return_error("something went wrong",
                                         response,
                                         StatusCode::InternalServerError);
            }
        };

        if url_matches(&request, Method::Get, "/api/auth") {
            // this URL only checks that the client can authenticate. they don't
            // care about the result
            let healthy = self.check_db(instance);
            return self.return_json(
                healthy,
                response);
        }

        return self.return_error(
            "unknown URL",
            response,
            StatusCode::NotFound);
    }
}

fn authenticate_request(instance: &SecretsServer, request: &Request) -> Result<User, SecretsError> {
    // all other requests require a client cert
    let ssl_info = match request.ssl::<SslStream<HttpStream>>() {
        None => {
            // uh?
            return Err(SecretsError::Authentication("not ssl?"));
        },
        Some(s) => s.ssl()
    };
    let client_pem = match ssl_info.peer_certificate() {
        None => {
            return return Err(SecretsError::Authentication("no client cert"));
        },
        Some(c) => c
    };
    let (remote_cn, remote_fingerprint) = match (client_pem.subject_name().text_by_nid(Nid::CN),
                                                 client_pem.fingerprint(HashType::SHA256)) {
        (Some(cn), Some(fingerprint)) => {
            (cn.to_string(), utils::hex(&fingerprint))
        },
        _ => {
            return return Err(SecretsError::Authentication("malformed client cert"));
        }
    };

    let user = try!(instance.authenticate(&remote_cn, &remote_fingerprint));
    return Ok(user);
}

fn _verify(_preverify_ok: bool, _ctx: &X509StoreContext) -> bool {
    // we need to set this callback in order for openssl to request the client
    // cert, but we don't verify it here
    return true;
}

fn make_ssl(instance: &mut SecretsServer) -> Result<Openssl, SecretsError> {
    let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1));
    ssl_context.set_verify(SSL_VERIFY_PEER, Some(_verify));
    let (public_pem, private_pem) = try!(instance.get_pems());
    try!(ssl_context.set_certificate(&public_pem));
    try!(ssl_context.set_private_key(&private_pem));
    try!(ssl_context.check_private_key());
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
