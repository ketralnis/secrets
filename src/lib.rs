#[cfg(test)] extern crate tempdir;
#[macro_use(quick_error)] extern crate quick_error;
#[macro_use] extern crate log;
extern crate byteorder;
extern crate chrono;
extern crate clap;
extern crate env_logger;
extern crate flate2;
extern crate hyper;
extern crate openssl;
extern crate regex;
extern crate rfc1751;
extern crate rusqlite;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;
extern crate tempfile;
extern crate termion;
extern crate url;

mod common;
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
