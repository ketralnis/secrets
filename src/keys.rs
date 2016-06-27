use std::io;
use std::io::{Read, Write};

use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::box_;
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

pub fn auth_items_with_password(items: &[&[u8]], password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let salt = pwhash::gen_salt();
    let key = try!(derive_auth_from_password(password, salt));

    let mut ret = vec![];

    // authed blob version
    try!(ret.write_u64::<NetworkEndian>(1));
    ret.extend_from_slice(&salt[..]);

    let blob = items.join(&b',');
    let tag = auth::authenticate(&blob, &key);

    ret.extend_from_slice(&tag[..]);

    return Ok(ret);
}

pub fn check_auth_items_with_password(items: &[&[u8]], expected_tag: &[u8], password: &[u8]) -> Result<bool, CryptoError> {
    let blob = items.join(&b',');

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

    return Ok(auth::verify(&tag, &blob, &key));
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
        let items = &[&b"bob"[..], &b"george"[..], &b"anthony"[..]];
        let good_password = b"correct horse battery staple";
        let sig = auth_items_with_password(items, good_password).unwrap();
        let verified = check_auth_items_with_password(items, &sig[..], good_password).unwrap();
        assert_eq!(true, verified);

        let bad_password = b"incorrect duck assault stapler";
        let verified = check_auth_items_with_password(items, &sig[..], bad_password).unwrap();
        assert_eq!(false, verified);

        let bad_items = &[&b"robert"[..], &b"georgia"[..], &b"tony"[..]];
        let verified = check_auth_items_with_password(bad_items, &sig[..], good_password).unwrap();
        assert_eq!(false, verified);
    }
}
