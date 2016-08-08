extern crate byteorder;
extern crate chrono;
extern crate clap;
extern crate env_logger;
extern crate flate2;
extern crate hyper;
extern crate libc;
#[macro_use]
extern crate log;
extern crate openssl;
#[macro_use(quick_error)]
extern crate quick_error;
extern crate regex;
extern crate rfc1751;
extern crate rusqlite;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;
#[cfg(test)]
extern crate tempdir;
extern crate tempfile;
extern crate url;

mod common;
mod getpass;
mod keys;
mod password;
mod utils;

pub mod client {
    mod client;
    pub mod client_cmd;
}

pub mod server {
    mod listener;
    mod server;
    pub mod server_cmd;
}

mod api {
    include!(concat!(env!("OUT_DIR"), "/api.rs"));
}
