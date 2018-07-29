#![feature(rust_2018_preview, use_extern_macros)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

#[macro_use]
mod utils;
mod api;
mod common;
mod getpass;
mod keys;
mod password;

pub mod client {
    mod client;
    pub mod client_cmd;
}

pub mod server {
    mod listener;
    mod server;
    pub mod server_cmd;
}
