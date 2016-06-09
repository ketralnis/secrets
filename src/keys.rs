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

pub fn create_key() -> (box_::PublicKey, box_::SecretKey) {
    let (public_key, private_key) = box_::gen_keypair();
    return (public_key, private_key);
}

pub fn derive_key_from_password(password: &str, salt: pwhash::Salt,
                                opslimit: pwhash::OpsLimit,
                                memlimit: pwhash::MemLimit)
                                -> Result<secretbox::Key, CryptoError> {
    let mut k = secretbox::Key([0; secretbox::KEYBYTES]);
    let secretbox::Key(ref mut kb) = k;
    let key = try!(pwhash::derive_key(kb, password.as_bytes(), &salt,
                                      pwhash::OPSLIMIT_INTERACTIVE,
                                      pwhash::MEMLIMIT_INTERACTIVE)
                    .map_err(|_: ()| CryptoError::Unknown));
    let key = try!(secretbox::Key::from_slice(key).ok_or(CryptoError::Unknown));
    Ok(key)
}

/// Encrypt a box_::SecretKey with a password, returning a blob that can be
/// stored and decrypted again later with that password
pub fn encrypt_key_with_password(private_key: &box_::SecretKey, password: &str)
        -> Result<Vec<u8>, CryptoError> {
    // derive the symetric encryption key from the password
    let opslimit = pwhash::OPSLIMIT_INTERACTIVE;
    let memlimit = pwhash::MEMLIMIT_INTERACTIVE;

    let nonce = secretbox::gen_nonce();
    let salt = pwhash::gen_salt();
    let key = try!(derive_key_from_password(password, salt, opslimit, memlimit));

    // encrypt with that key
    let ciphertext = secretbox::seal(&private_key[..], &nonce, &key);

    // turn that into our stored format which includes the nonce and stuff
    let mut ret = vec![];

    // encrypted blob version
    try!(ret.write_u16::<NetworkEndian>(1));

    // the settings to derive the key from the password
    try!(ret.write_u64::<NetworkEndian>(opslimit.0 as u64));
    try!(ret.write_u64::<NetworkEndian>(memlimit.0 as u64));

    // the sizes of these are defined by the cipher suite
    ret.extend_from_slice(&salt[..]);
    ret.extend_from_slice(&nonce[..]);

    // and the rest is the actual ciphertext
    ret.extend_from_slice(&ciphertext[..]);

    Ok(ret)
}

/// Decrypt a blob that has been stored with encrypt_key_with_poassword into a
/// box_::SecretKey. **Note** it is not safe to use this to decrypt blobs
/// received from untrusted sources (as the work factors for the KDF are
/// included unauthenticated in the blob, so an attacker could cause them to be
/// arbitrarily expensive)
pub fn decrypt_key_with_password(blob: &[u8], password: &str) -> Result<box_::SecretKey, CryptoError> {
    if blob.len() <= pwhash::SALTBYTES + secretbox::NONCEBYTES {
        return Err(CryptoError::CantDecrypt);
    }

    let mut rdr = io::Cursor::new(blob);

    let version = try!(rdr.read_u16::<NetworkEndian>());
    if version != 1 { return Err(CryptoError::CantDecrypt); }

    let opslimit = try!(rdr.read_u64::<NetworkEndian>()) as usize;
    let opslimit = pwhash::OpsLimit(opslimit);
    let memlimit = try!(rdr.read_u64::<NetworkEndian>()) as usize;
    let memlimit = pwhash::MemLimit(memlimit);

    let mut salt: Vec<u8> = vec![0; pwhash::SALTBYTES];
    try!(rdr.read(&mut salt));
    let salt = try!(pwhash::Salt::from_slice(&salt).ok_or(CryptoError::CantDecrypt));

    let mut nonce: Vec<u8> = vec![0; secretbox::NONCEBYTES];
    try!(rdr.read(&mut nonce));
    let nonce = try!(secretbox::Nonce::from_slice(&nonce).ok_or(CryptoError::CantDecrypt));

    let mut ciphertext: Vec<u8> = vec![];
    try!(rdr.read_to_end(&mut ciphertext));

    let derived_key = try!(derive_key_from_password(password, salt,
                                                    opslimit, memlimit));

    let plaintext = try!(secretbox::open(&ciphertext, &nonce, &derived_key)
                        .map_err(|_: ()| CryptoError::CantDecrypt));

    // what's encrypted is a private key, so make that out of the plaintext
    let private_key = try!(box_::SecretKey::from_slice(&plaintext).ok_or(CryptoError::Unknown));
    Ok(private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_encrypt_key_with_password() {
        let (public, private) = create_key();
        let password = "correct horse battery stable";
        let encrypted_key = encrypt_key_with_password(&private, password).unwrap();
        let decrypted_key = decrypt_key_with_password(&encrypted_key, password).unwrap();
        assert_eq!(private, decrypted_key);
    }

    #[test]
    #[should_panic]
    pub fn test_encrypt_key_with_wrong_password() {
        let (public, private) = create_key();
        let good_password = "correct horse battery stable";
        let wrong_password = "not the right password";
        let encrypted_key = encrypt_key_with_password(&private, good_password).unwrap();
        let decrypted_key = decrypt_key_with_password(&encrypted_key, wrong_password).unwrap();
        assert_eq!(private, decrypted_key);
    }
}
