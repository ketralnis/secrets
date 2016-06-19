use std::io;
use std::io::{Read, Write};

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

pub fn create_keypair() -> (box_::PublicKey, box_::SecretKey) {
    let (public_key, private_key) = box_::gen_keypair();
    return (public_key, private_key);
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
    if blob.len() <= pwhash::SALTBYTES + secretbox::NONCEBYTES {
        return Err(CryptoError::CantDecrypt);
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_encrypt_blob_with_password() {
        let blob = "this is a blob".as_bytes();
        let password = "correct horse battery stable".as_bytes();
        let encrypted_blob = encrypt_blob_with_password(blob, password).unwrap();
        let decrypted_blob = decrypt_blob_with_password(&encrypted_blob, password).unwrap();
        assert_eq!(blob.to_vec(), decrypted_blob);
    }

    #[test]
    #[should_panic]
    pub fn test_encrypt_blob_with_wrong_password() {
        let blob = "this is another blob".as_bytes();
        let good_password = "correct horse battery stable".as_bytes();
        let wrong_password = "not the right password".as_bytes();
        let encrypted_blob = encrypt_blob_with_password(blob, good_password).unwrap();
        let decrypted_blob = decrypt_blob_with_password(&encrypted_blob, wrong_password).unwrap();
        assert_eq!(blob.to_vec(), decrypted_blob);
    }
}
