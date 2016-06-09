use std::path::Path;

use rusqlite;

use keys;

pub struct ServerDb {
    conn: rusqlite::Connection
}

impl ServerDb {
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        ServerDb::_connect(path, true)
    }

    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        ServerDb::_connect(path, false)
    }

    pub fn _connect<P: AsRef<Path>>(path: P, create: bool) -> Result<Self, rusqlite::Error> {
        let flags = if create {
            rusqlite::SQLITE_OPEN_READ_WRITE | rusqlite::SQLITE_OPEN_CREATE
        } else {
            rusqlite::SQLITE_OPEN_READ_WRITE
        };
        let mut conn = try!(rusqlite::Connection::open_with_flags(path, flags));
        try!(pragmas(&mut conn));
        if create {
            try!(create_schema(&mut conn));
        }
        Ok(ServerDb {conn: conn})
    }

    pub fn check_db(&mut self) -> Result<(), rusqlite::Error> {
        self.conn.query_row("select 1", &[], |_| ())
    }
}

fn pragmas(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    // sqlite config that must be done on every connection
    conn.execute_batch("
        PRAGMA application_id=0x53435253; -- SCRS
        PRAGMA foreign_keys=ON;
        PRAGMA journal_mode=DELETE;
        PRAGMA secure_delete=true;

        -- this is a (probably misguided) attempt to keep password data off of
        -- disk at the expense of potentially crashing with OOM
        PRAGMA temp_store=MEMORY;
    ")
}

fn create_schema(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
    try!(conn.execute_batch("
        CREATE TABLE globals (
            key PRIMARY KEY,
            value
        );
        CREATE TABLE users (
            user_name PRIMARY KEY,
            user_email,
            created INTEGER,
            modified INTEGER,
            public_key,
            disabled INTEGER NULL DEFAULT NULL
        );
        CREATE TABLE services (
            service_name PRIMARY KEY,
            created INTEGER,
            modified INTEGER,
            creator REFERENCES users(user_name),
            last_set_by REFERENCES users(user_name)
        );
        CREATE TABLE authorizations (
            user_name REFERENCES users(user_name),
            service_name REFERENCES services(service_name),
            created INTEGER,
            modified INTEGER,
            grantor REFERENCES users(user_name), -- who initially gave them permission
            last_set_by REFERENCES users(user_name),
            ciphertext, -- encrypted to user_name's public key
            PRIMARY KEY(user_name, service_name)
        );
    "));
    let (public_key, private_key) = keys::create_key();
    let public_key = &public_key[..];
    let private_key = &private_key[..];
    try!(conn.execute("
        INSERT INTO globals(key, value) VALUES('public_key',?)
    ", &[&public_key]));
    try!(conn.execute("
        INSERT INTO globals(key, value) VALUES('private_key',?)
    ", &[&private_key]));
    Ok(())
}
