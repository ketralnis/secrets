/// code shared by SecretsClient and SecretsServer

use std::io;
use openssl::ssl::error::SslError;
use openssl::x509::X509Generator;
use openssl::x509::extension::KeyUsageOption::DigitalSignature;
use openssl::crypto::hash::Type as HashType;
use openssl::x509::extension::Extension::KeyUsage;

use hyper;
use rusqlite;

use keys;

quick_error! {
    #[derive(Debug)]
    pub enum SecretsError {
        Sqlite(err: rusqlite::Error) {from()}
        Ssl(err: SslError) {from()}
        Crypto(err: keys::CryptoError) {from()}
        HyperError(err: hyper::Error) {from()}
        Io(err: io::Error) {from()}
        ServerError(err: String) {} // client had a problem communicating with server
        Unknown(err: &'static str) {}

        NotImplemented(err: &'static str) {}
    }
}
pub fn init_ssl_cert<'ctx>(cn: &str) -> Result<(Vec<u8>, Vec<u8>), SecretsError> {
    let gen = X509Generator::new()
        .set_bitlength(4096)
        .add_name("CN".to_owned(), cn.to_string())
        .set_sign_hash(HashType::SHA256)
        .add_extension(KeyUsage(vec![DigitalSignature])); // so that we can sign client certs
    let (public_pem, private_pem) = try!(gen.generate());

    let mut public_pem_vec = vec![];
    try!(public_pem.write_pem(&mut public_pem_vec));

    let mut private_pem_vec = vec![];
    try!(private_pem.write_pem(&mut private_pem_vec));

    return Ok((public_pem_vec, private_pem_vec));
}
