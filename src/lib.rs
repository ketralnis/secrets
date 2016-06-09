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

// external binaries' entry points
pub mod client_cmd;
pub mod server_cmd;

mod utils;
mod keys;
mod password;

mod server_db;
mod server;
mod client;
