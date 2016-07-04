use std::io;
use std::io::{Read, Write};

use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::pwhash;
use byteorder::{NetworkEndian, WriteBytesExt, ReadBytesExt};

quick_error! {
    #[derive(Debug)]
    pub enum CryptoError {
        Io(err: io::Error) { from() }
        CantDecrypt
        Unknown
    }
}

pub fn derive_key_from_password(password: &[u8], salt: pwhash::Salt)
                                -> Result<secretbox::Key, CryptoError> {
    let mut k = secretbox::Key([0; secretbox::KEYBYTES]);
    let secretbox::Key(ref mut kb) = k;

    // the ops/mem limits can only be changed with a version increment in
    // encrypt_blob_with_password/decrypt_blob_with_password
    let key = try!(pwhash::derive_key(kb, password, &salt,
                                      pwhash::OPSLIMIT_INTERACTIVE,
                                      pwhash::MEMLIMIT_INTERACTIVE)
                    .map_err(|_: ()| CryptoError::Unknown));
    let key = try!(secretbox::Key::from_slice(key).ok_or(CryptoError::Unknown));
    Ok(key)
}

pub fn derive_auth_from_password(password: &[u8], salt: pwhash::Salt)
                                 -> Result<auth::Key, CryptoError> {
    let mut k = auth::Key([0; auth::KEYBYTES]);
    let auth::Key(ref mut kb) = k;

    // the ops/mem limits can only be changed with a version increment in
    // auth_items_with_password/check_auth_items_with_password
    let key = try!(pwhash::derive_key(kb, password, &salt,
                                      pwhash::OPSLIMIT_INTERACTIVE,
                                      pwhash::MEMLIMIT_INTERACTIVE)
                    .map_err(|_: ()| CryptoError::Unknown));
    let key = try!(auth::Key::from_slice(key).ok_or(CryptoError::Unknown));
    Ok(key)
}

/// Encrypt a blob with a password, returning a blob that can be
/// stored and decrypted again later with that password
pub fn encrypt_blob_with_password(value: &[u8], password: &[u8])
        -> Result<Vec<u8>, CryptoError> {
    // derive the symetric encryption key from the password
    let nonce = secretbox::gen_nonce();
    let salt = pwhash::gen_salt();
    let key = try!(derive_key_from_password(password, salt));

    // encrypt with that key
    let ciphertext = secretbox::seal(value, &nonce, &key);

    // turn that into our stored format which includes the nonce and stuff
    let mut ret = vec![];

    // encrypted blob version
    try!(ret.write_u64::<NetworkEndian>(1));

    // the sizes of these are defined by the cipher suite
    ret.extend_from_slice(&salt[..]);
    ret.extend_from_slice(&nonce[..]);

    // and the rest is the actual ciphertext
    ret.extend_from_slice(&ciphertext[..]);

    Ok(ret)
}

/// Decrypt a blob that has been stored with encrypt_blob_with_password.
/// **Note** it is not safe to use this to decrypt blobs received from untrusted
/// sources (as the work factors for the KDF are included unauthenticated in the
/// blob, so an attacker could cause them to be arbitrarily expensive)
pub fn decrypt_blob_with_password(blob: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut rdr = io::Cursor::new(blob);

    let version = try!(rdr.read_u64::<NetworkEndian>());
    if version != 1 { return Err(CryptoError::CantDecrypt); }

    let mut salt: Vec<u8> = vec![0; pwhash::SALTBYTES];
    try!(rdr.read(&mut salt));
    let salt = try!(pwhash::Salt::from_slice(&salt).ok_or(CryptoError::CantDecrypt));

    let mut nonce: Vec<u8> = vec![0; secretbox::NONCEBYTES];
    try!(rdr.read(&mut nonce));
    let nonce = try!(secretbox::Nonce::from_slice(&nonce).ok_or(CryptoError::CantDecrypt));

    let mut ciphertext: Vec<u8> = vec![];
    try!(rdr.read_to_end(&mut ciphertext));

    let derived_key = try!(derive_key_from_password(password, salt));

    let plaintext = try!(secretbox::open(&ciphertext, &nonce, &derived_key)
                        .map_err(|_: ()| CryptoError::CantDecrypt));
    return Ok(plaintext);
}

pub fn auth_items_with_password(items: &Authable, password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let salt = pwhash::gen_salt();
    let key = try!(derive_auth_from_password(password, salt));

    let mut ret = vec![];

    // authed blob version
    try!(ret.write_u64::<NetworkEndian>(1));
    ret.extend_from_slice(&salt[..]);

    let blob = items.to_authable();
    let tag = auth::authenticate(&blob, &key);

    ret.extend_from_slice(&tag[..]);

    return Ok(ret);
}

pub fn check_auth_items_with_password(items: &Authable, expected_tag: &[u8],
                                      password: &[u8]) -> Result<(), CryptoError> {
    let blob = items.to_authable();

    let mut rdr = io::Cursor::new(expected_tag);

    let version = try!(rdr.read_u64::<NetworkEndian>());
    if version != 1 { return Err(CryptoError::CantDecrypt); }

    let mut salt: Vec<u8> = vec![0; pwhash::SALTBYTES];
    try!(rdr.read(&mut salt));
    let salt = try!(pwhash::Salt::from_slice(&salt).ok_or(CryptoError::CantDecrypt));
    let key = try!(derive_auth_from_password(password, salt));

    let mut tag_bytes = vec![];
    try!(rdr.read_to_end(&mut tag_bytes));
    let tag = try!(auth::Tag::from_slice(&tag_bytes).ok_or(CryptoError::CantDecrypt));

    let authed = auth::verify(&tag, &blob, &key);

    if authed {
        return Ok(())
    } else {
        return Err(CryptoError::CantDecrypt)
    }
}

/// Trait for things that we can build authentication tokens out of
pub trait Authable {
    fn to_authable(&self) -> Vec<u8>;
}

impl<'a, 'b> Authable for &'a [&'b Authable] {
    fn to_authable(&self) -> Vec<u8> {
        let mapped = self.iter().map(|v| v.to_authable());
        let collected: Vec<Vec<u8>> = mapped.collect();
        let joined = collected.join(&b',');
        joined
    }
}

impl Authable for String {
    fn to_authable(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Authable for i64 {
    fn to_authable(&self) -> Vec<u8> {
        let s = format!("{}", self);
        s.as_bytes().to_vec()
    }
}

impl Authable for Option<i64> {
    fn to_authable(&self) -> Vec<u8> {
        let s = match *self {
            Some(x) => format!("Some({})", x),
            None => "None".to_string(),
        };
        s.as_bytes().to_vec()
    }
}

impl<'a> Authable for &'a [u8] {
    fn to_authable(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Authable for Vec<u8> {
    fn to_authable(&self) -> Vec<u8> {
        self.to_owned()
    }
}

impl<'a> Authable for &'a str {
    fn to_authable<'b>(&'b self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Authable for box_::PublicKey {
    fn to_authable<'a>(&'a self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl Authable for sign::PublicKey {
    fn to_authable<'a>(&'a self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_encrypt_blob_with_password() {
        let blob = b"this is a blob";
        let password = b"correct horse battery staple";
        let encrypted_blob = encrypt_blob_with_password(blob, password).unwrap();
        let decrypted_blob = decrypt_blob_with_password(&encrypted_blob, password).unwrap();
        assert_eq!(blob.to_vec(), decrypted_blob);
    }

    #[test]
    #[should_panic]
    pub fn test_encrypt_blob_with_wrong_password() {
        let blob = b"this is another blob";
        let good_password = b"correct horse battery staple";
        let wrong_password = b"not the right password";
        let encrypted_blob = encrypt_blob_with_password(blob, good_password).unwrap();
        let decrypted_blob = decrypt_blob_with_password(&encrypted_blob, wrong_password).unwrap();
        assert_eq!(blob.to_vec(), decrypted_blob);
    }

    #[test]
    pub fn test_auth_items() {
        let items: &[&Authable] = &[&"bob", &"george", &"anthony"];
        let good_password = b"correct horse battery staple";
        let sig = auth_items_with_password(&items, good_password).unwrap();
        let verified = check_auth_items_with_password(&items, &sig[..], good_password);
        assert_eq!(true, verified.is_ok());

        let bad_password = b"incorrect duck assault stapler";
        let verified = check_auth_items_with_password(&items, &sig[..], bad_password);
        assert_eq!(true, verified.is_err());

        let bad_items: &[&Authable] = &[&"robert", &"georgia", &"tony"];
        let verified = check_auth_items_with_password(&bad_items, &sig[..], good_password);
        assert_eq!(true, verified.is_err());
    }
}
