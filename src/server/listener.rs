use std::collections::HashMap;
use std::io::Error as IOError;
use std::sync::Arc;
use std::sync::Mutex;

use hyper::method::Method;
use hyper::net::HttpStream;
use hyper::net::Openssl;
use hyper::server::{Handler, Request, Response};
use hyper::server::Server as HyperServer;
use hyper::status::StatusCode;
use hyper::uri::RequestUri;
use openssl::crypto::hash::Type as HashType;
use openssl::nid::Nid;
use openssl::ssl::{SSL_VERIFY_PEER, SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3, SSL_OP_NO_COMPRESSION};
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::ssl::SslStream;
use openssl::x509::X509StoreContext;
use rustc_serialize::hex::ToHex;
use serde_json::ser::to_string as json_to_string;
use url::form_urlencoded::parse as parse_qs;

use api::{User, Service, Grant, PeerInfo, ApiResponse};
use common::SecretsContainer;
use common::SecretsError;
use server::server::SecretsServer;

struct ServerHandler {
    instance: Arc<Mutex<SecretsServer>>
}

impl ServerHandler {
    fn _handle(&self,
               instance: &mut SecretsServer,
               request: &Request)
            -> Result<(StatusCode, ApiResponse), SecretsError> {

        let mut api = ApiResponse::new();

        if url_matches(&request, Method::Get, "/api/health") {
            try!(instance.check_db());
            api.healthy = Some(true);
            return Ok((StatusCode::Ok, api));
        }

        if url_matches(&request, Method::Get, "/api/info") {
            let cn = try!(instance.ssl_cn());
            let fingerprint = try!(instance.ssl_fingerprint());
            let (public_key, _) = try!(instance.get_keys());
            let (public_sign, _) = try!(instance.get_signs());

            let server_info = PeerInfo {
                cn: cn,
                fingerprint: fingerprint,
                public_key: public_key,
                public_sign: public_sign,
            };
            api.server_info = Some(server_info);
            return Ok((StatusCode::Ok, api));
        }

        // ================ authentication required from here ================

        let user = try!(authenticate_request(&instance, &request));

        if url_matches(&request, Method::Get, "/api/auth") {
            // this URL only checks that the client can authenticate. they don't
            // really care about the result
            api.users.insert(user.username.clone(), user.clone());
            return Ok((StatusCode::Ok, api));
        }

        let query_params: HashMap<String, Vec<String>> = get_query_params(&request);

        if url_matches(&request, Method::Get, "/api/users") {
            let unames = query_params.get("user");

            if let Some(unames) = unames {
                for ref uname in unames {
                    let user = try!(instance.get_user(uname));
                    api.users.insert(user.username.clone(), user);
                }
            }
            return Ok((StatusCode::Ok, api))
        }

        if url_matches(&request, Method::Get, "/api/services") {
            let names = query_params.get("service");

            if let Some(names) = names {
                for ref name in names {
                    let service = try!(instance.get_service(name));
                    api.services.insert(service.name.clone(), service);
                }
            }
            return Ok((StatusCode::Ok, api))
        }

        if url_matches(&request, Method::Get, "/api/grants") {
            let names = query_params.get("grant");

            if let Some(names) = names {
                for ref name in names {
                    let (service_name, grantee_name) = Grant::split_key(name);

                    let grant = try!(instance.get_grant(&service_name, &grantee_name));

                    // add in the dependent fields

                    let grantee = try!(instance.get_user(&grantee_name));
                    api.users.insert(grantee.username.clone(), grantee);

                    let grantor = try!(instance.get_user(&grant.grantor));
                    api.users.insert(grantor.username.clone(), grantor);

                    let service = try!(instance.get_service(&service_name));
                    api.services.insert(service.name.clone(), service);

                    api.grants.insert(grant.key(), grant);
                }
            }
            return Ok((StatusCode::Ok, api))
        }

        return Ok((StatusCode::NotFound, api))
    }

    fn write_response(&self,
                      status_code: StatusCode,
                      api: ApiResponse,
                      mut response: Response) -> Result<(), SecretsError> {
        match json_to_string(&api) {
            Ok(value_str) => {
                *response.status_mut() = status_code;
                try!(response.send(value_str.as_bytes()));
                Ok(())
            },
            Err(error) => {
                error!("Error encoding JSON: {:?}", error);
                *response.status_mut() = StatusCode::InternalServerError;
                try!(response.start());
                Ok(())
            }
        }
    }

    fn write_error(&self,
                   error: &SecretsError,
                   mut response: Response)
                   -> Result<(), IOError> {
        // Secrets has two kinds of errors: A regular ApiResponse can have
        // `error` set on it in which case write_response will handle it.
        // Otherwise if an Error (in the rust keyword sense) is raised during
        // processing, we get called with it. We try to guess the right return
        // code to set

        match error {
            &SecretsError::ClientError(ref err) => {
                *response.status_mut() = StatusCode::BadRequest;
                response.send(&format!("{}", err).as_bytes())
            },
            &SecretsError::Authentication(ref err) => {
                *response.status_mut() = StatusCode::Unauthorized;
                response.send(&format!("{}", err).as_bytes())
            },
            &SecretsError::Crypto(_) | _ => {
                // SecretsError::Crypto is probably because they are screwing
                // around with trying to guess keys or something. It's important
                // that they not be able to tell it from any other internal
                // error
                *response.status_mut() = StatusCode::InternalServerError;
                response.send(b"")
            },
        }
    }
}

impl Handler for ServerHandler {
    fn handle(&self, request: Request, response: Response) -> () {
        // every request takes out a lock on the SecretsServer instance. This
        // means that we have no real concurrency to speak of, anywhere in the
        // server. It doesn't have to be this way but this simplifies things
        // signficantly (no DB connection pooling or anything). If this is a
        // performance problem it can be fixed, but I doubt we'll ever see real
        // concurrent connections to speak of
        let mut instance = self.instance.lock().unwrap();

        match self._handle(&mut instance, &request) {
            Ok((status_code, api_response)) => {
                debug!("response({:?}): {:?}", status_code, api_response);
                match self.write_response(status_code, api_response, response) {
                    Ok(()) => (), // all good!
                    Err(err) => {
                        // the request was a success, but we couldn't write it
                        // out. this is probably a closed socket
                        error!("Error writing response {:?}", err);
                    }
                }
            },
            Err(err_o) => {
                error!("request error {:?}", err_o);
                match self.write_error(&err_o, response) {
                    Ok(()) => {
                        // this is a regular old error during request
                        // processing. it's probably a bug but could be bad
                        // ciphertext or something
                        ()
                    }
                    Err(err_i) => {
                        error!("Error writing error {:?}: {:?}", err_o, err_i);
                    }
                }
            }
        }
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
            (cn.to_string(), fingerprint.to_hex())
        },
        _ => {
            return Err(SecretsError::Authentication("malformed client cert"));
        }
    };

    let user = try!(instance.authenticate(&remote_cn, &remote_fingerprint));
    return Ok(user);
}

fn pretend_verify(_preverify_ok: bool, _ctx: &X509StoreContext) -> bool {
    // we need to set this callback in order for openssl to request the client
    // cert, but we don't verify it here
    return true;
}

fn make_ssl(instance: &mut SecretsServer) -> Result<Openssl, SecretsError> {
    let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1));
    ssl_context.set_verify(SSL_VERIFY_PEER, Some(pretend_verify));
    ssl_context.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);
    try!(ssl_context.set_cipher_list("ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4@STRENGTH"));
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
    info!("terminating (hyper_server.handle returned)");
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

fn get_query_params(request: &Request) -> HashMap<String, Vec<String>> {
    let mut ret = HashMap::new();

    let uri = match request.uri {
        RequestUri::AbsolutePath(ref x) => x,
        _ => {
            return ret;
        }
    };

    if !uri.contains("?") {
        return ret;
    }

    let params = uri.splitn(2, "?").nth(1).unwrap();

    for (ref key, ref value) in parse_qs(params.as_bytes()) {
        let key = key.to_string();
        let value = value.to_string();
        let vec = ret.entry(key).or_insert_with(|| vec![]);
        (*vec).push(value);
    }

    return ret;
}
