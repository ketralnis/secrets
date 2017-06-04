// API objects that are passed via HTTP, implemented with serde code generation
// for convenience

use std::collections::HashMap;
use std::io::Cursor;
use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use rfc1751::ToRfc1751;
use rusqlite;
use rustc_serialize::base64::STANDARD as STANDARD_BASE64_CONFIG;
use rustc_serialize::base64::{FromBase64, ToBase64};
use rustc_serialize::hex::{ToHex, FromHex};
use serde_json::from_slice as json_from_slice;
use serde_json::ser::to_string as json_to_string;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash::sha256;

use common::SecretsError;
use keys::CryptoError;
use keys;
use utils::pretty_date;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub public_key: box_::PublicKey,
    pub public_sign: sign::PublicKey,
    pub ssl_fingerprint: String,
    pub created: i64,
    pub disabled: Option<i64>,
}

impl User {
    pub fn from_row(row: &rusqlite::Row) -> Result<Self, SecretsError> {
        let public_key: Vec<u8> = row.get("public_key");
        let public_key = try!(box_::PublicKey::from_slice(&public_key.as_ref())
            .ok_or(CryptoError::CantDecrypt));

        let public_sign: Vec<u8> = row.get("public_sign");
        let public_sign =
            try!(sign::PublicKey::from_slice(&public_sign.as_ref())
                .ok_or(CryptoError::CantDecrypt));

        let u = User {
            username: row.get("username"),
            public_key: public_key,
            public_sign: public_sign,
            ssl_fingerprint: row.get("ssl_fingerprint"),
            created: row.get("created"),
            disabled: row.get("disabled"),
        };
        Ok(u)
    }

    pub fn to_peer_info(&self) -> PeerInfo {
        PeerInfo {
            cn: self.username.clone(),
            fingerprint: self.ssl_fingerprint.clone(),
            public_key: self.public_key.clone(),
            public_sign: self.public_sign.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub created: i64,
    pub modified: i64,
    pub creator: String,
    pub modified_by: String,
}

impl Service {
    pub fn from_row(row: &rusqlite::Row) -> Result<Self, SecretsError> {
        let s = Service {
            name: row.get("service_name"),
            created: row.get("created"),
            modified: row.get("modified"),
            creator: row.get("creator"),
            modified_by: row.get("modified_by"),
        };
        Ok(s)
    }

    pub fn printable_report(&self) -> String {
        return format!("=== {} ===\n\
                       name:        {}\n\
                       created:     {}\n\
                       modified:    {}\n\
                       creator:     {}\n\
                       modified by: {}\
                       ",
                       self.name,
                       self.name,
                       pretty_date(self.created),
                       pretty_date(self.modified),
                       self.creator,
                       self.modified_by)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Grant {
    pub grantee: String,
    pub grantor: String,
    pub service_name: String,
    pub ciphertext: Vec<u8>,
    pub created: i64,
    pub signature: sign::Signature,
}

impl Grant {
    pub fn create(grantee: String,
                  grantor: String,
                  service_name: String,
                  plaintext: &[u8],
                  created: i64,
                  from_key: &box_::SecretKey,
                  to_key: &box_::PublicKey,
                  from_sign: &sign::SecretKey)
                  -> Result<Self, SecretsError> {
        let ciphertext = try!(keys::encrypt_to(plaintext, from_key, to_key));
        let signable = Self::signable(&grantee,
                                      &grantor,
                                      &service_name,
                                      &ciphertext,
                                      created);
        let signature = sign::sign_detached(&signable, &from_sign);
        let grant = Grant {
            grantee: grantee,
            grantor: grantor,
            service_name: service_name,
            ciphertext: ciphertext,
            created: created,
            signature: signature,
        };
        Ok(grant)
    }

    pub fn from_row(row: &rusqlite::Row) -> Result<Self, SecretsError> {
        let sig: Vec<u8> = row.get("signature");
        let signature = try!(sign::Signature::from_slice(&sig)
            .ok_or(CryptoError::CantDecrypt));

        let u = Grant {
            grantee: row.get("grantee"),
            grantor: row.get("grantor"),
            service_name: row.get("service_name"),
            ciphertext: row.get("ciphertext"),
            signature: signature,
            created: row.get("created"),
        };
        Ok(u)
    }

    fn signable(grantee: &str,
                grantor: &str,
                service_name: &str,
                ciphertext: &[u8],
                created: i64)
                -> Vec<u8> {
        let mut ret: Vec<u8> = vec![];
        ret.extend_from_slice(&grantee.as_bytes());
        ret.extend_from_slice(&b","[..]);
        ret.extend_from_slice(&grantor.as_bytes());
        ret.extend_from_slice(&b","[..]);
        ret.extend_from_slice(&service_name.as_bytes());
        ret.extend_from_slice(&b","[..]);
        ret.extend_from_slice(ciphertext);
        ret.extend_from_slice(&b","[..]);
        ret.extend_from_slice(&format!("{}", created).as_bytes());
        ret.extend_from_slice(&b","[..]);
        ret
    }

    fn _signable(&self) -> Vec<u8> {
        Self::signable(&self.grantee,
                       &self.grantor,
                       &self.service_name,
                       &self.ciphertext,
                       self.created)
    }

    pub fn verify_signature(&self, grantor_public_sign: &sign::PublicKey) -> Result<(), CryptoError> {
        let signable = self._signable();
        if !sign::verify_detached(&self.signature,
                                  &signable,
                                  grantor_public_sign) {
            return Err(CryptoError::CantDecrypt);
        }
        Ok(())
    }

    pub fn decrypt(&self,
                   grantee_public_key: &box_::PublicKey,
                   grantor_private_key: &box_::SecretKey)
                   -> Result<Vec<u8>, CryptoError> {
        let decrypted = try!(keys::decrypt_from(&self.ciphertext,
                                                &grantee_public_key,
                                                &grantor_private_key));
        Ok(decrypted)
    }

    pub fn key(&self) -> String {
        Self::key_for(&self.service_name, &self.grantee)
    }

    pub fn key_for(service_name: &str, grantee: &str) -> String {
        format!("{}::{}", service_name, grantee)
    }

    pub fn split_key(key: &str) -> (String, String) {
        let splitted: Vec<&str> = key.splitn(2, "::")
            .collect();
        (splitted[0].to_string(), splitted[1].to_string())
    }

    pub fn printable_report(&self) -> String {
        format!("=== {} === \n\
                key:          {}\n\
                grantee:      {}\n\
                grantor:      {}\n\
                service name: {}\n\
                cipherlength: {}\n\
                created:      {}",
                self.key(),
                self.key(),
                self.grantee,
                self.grantor,
                self.service_name,
                self.ciphertext.len(),
                pretty_date(self.created))
    }

    pub fn clap_validate_name(name: String) -> Result<(), String> {
        if (&name).contains("::") {
            Ok(())
        } else {
            Err("must contain ::".to_string())
        }
    }

}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    pub healthy: Option<bool>,
    pub users: HashMap<String, User>,
    pub services: HashMap<String, Service>,
    pub grants: HashMap<String, HashMap<String, Grant>>,
    pub error: Option<String>,
    pub server_info: Option<PeerInfo>,
}

impl ApiResponse {
    pub fn new() -> Self {
        ApiResponse {
            healthy: None,
            users: HashMap::new(),
            services: HashMap::new(),
            grants: HashMap::new(),
            error: None,
            server_info: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerInfo {
    pub cn: String,
    pub fingerprint: String,
    pub public_key: box_::PublicKey,
    pub public_sign: sign::PublicKey,
}

impl PeerInfo {
    pub fn printable_report(&self) -> Result<String, SecretsError> {
        let fingerprint_hex = &self.fingerprint;
        let public_key_hex = self.public_key.as_ref().to_hex();
        let public_sign_hex = self.public_sign.as_ref().to_hex();
        let mnemonic = try!(self.mnemonic());

        Ok(format!("=== {} ===\n\
                   common name: {}\n\
                   fingerprint: {}\n\
                   public key:  {}\n\
                   public sign: {}\n\
                   mnemonic:    {}",
                   self.cn,
                   self.cn,
                   fingerprint_hex,
                   public_key_hex,
                   public_sign_hex,
                   mnemonic))
    }

    fn mnemonic(&self) -> Result<String, SecretsError> {
        let fingerprint_bytes = try!(self.fingerprint.from_hex());
        let mut ret = Vec::new();
        ret.extend_from_slice(&self.cn.as_bytes());
        ret.extend_from_slice(&fingerprint_bytes);
        ret.extend_from_slice(&self.public_key.as_ref());
        ret.extend_from_slice(&self.public_sign.as_ref());
        let ret = sha256::hash(ret.as_slice());
        let ret = try!((&ret[..]).to_rfc1751());
        Ok(ret)
    }
}

/// What a new unauthorised client sends (offline via an admin with login
/// access) to the server to request its keys be authorized on the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub server_info: PeerInfo,
    pub client_info: PeerInfo,
}

impl JoinRequest {
    pub fn to_pastable(&self) -> Result<String, SecretsError> {
        let as_json_string = try!(json_to_string(&self));
        let mut encoder = GzEncoder::new(Vec::new(), Compression::Best);
        try!(encoder.write_all(&as_json_string.as_bytes()));
        let compressed = try!(encoder.finish());
        let b64 = compressed.to_base64(STANDARD_BASE64_CONFIG);
        Ok(b64)
    }

    pub fn from_pastable(data: &[u8]) -> Result<Self, SecretsError> {
        let unb64d = try!(data.from_base64()
            .map_err(|_| CryptoError::CantDecrypt));
        let cursor = Cursor::new(unb64d);
        let mut decoder = try!(GzDecoder::new(cursor));
        let mut decompressed = Vec::new();
        try!(decoder.read_to_end(&mut decompressed)
            .map_err(|_| CryptoError::CantDecrypt));
        let ret = try!(json_from_slice(&decompressed));
        Ok(ret)
    }
}

/// A request from the client to create a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCreateRequest {
    pub service: Service,
    pub grants: Vec<Grant>,
}

/// A request from the client to add grants to or rotate a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRequest {
    pub service_name: String,
    pub grants: Vec<Grant>,
}
