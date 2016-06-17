#[macro_use(quick_error)] extern crate quick_error;
extern crate sodiumoxide;
extern crate hyper;
extern crate regex;
extern crate rusqlite;
extern crate clap;
extern crate openssl;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate rpassword;
extern crate serde_json;
extern crate term;
extern crate byteorder;
#[cfg(test)] extern crate tempdir;

mod utils;
mod keys;
mod password;

pub mod client {
    pub mod client_cmd;
    mod client;
}

pub mod server {
    pub mod server_cmd;
    mod server;
    mod listener;
}
