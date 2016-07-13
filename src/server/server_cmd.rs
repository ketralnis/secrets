use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::exit;

use clap::{Arg, App, AppSettings, SubCommand};
use env_logger;
use openssl::ssl::init as init_openssl;
use sodiumoxide;

use api::JoinRequest;
use client::client_cmd::PASSWORD_SOURCE_HELP;
use password;
use server::listener;
use server::server;
use utils;

pub fn main() {
    let matches = App::new("secrets-server")
        .arg(Arg::with_name("db")
             .short("d").long("db")
             .value_name("DB_FILE")
             .help("path to the secrets database file")
             .required(true)
             .takes_value(true))
        .arg(Arg::with_name("password")
             .short("p").long("--password")
             .value_name("PASSWORD-SOURCE")
             .help(PASSWORD_SOURCE_HELP)
             .takes_value(true)
             .default_value("pass:") // empty password
             .validator(password::validate_password_source))
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("init")
            .help("initialise the database")
            .arg(Arg::with_name("name")
                 .short("n").long("name")
                 .help("the hostname that others will use to contact me")
                 .takes_value(true)
                 .required(true)))
        .subcommand(SubCommand::with_name("server")
            .about("bring up the secrets server")
            .arg(Arg::with_name("listen")
                .short("l").long("listen")
                .takes_value(true)
                .default_value("0.0.0.0:4430")
                .validator(|l| utils::validate_host("listen", &l))))
        .subcommand(SubCommand::with_name("accept-join")
            .about("Process a join request from a user")
            .arg(Arg::with_name("filename")
                .index(1)
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("server-info")
            .about("show info about the server"))
        .get_matches();

    init_openssl();
    env_logger::init().unwrap();
    sodiumoxide::init();

    let mut config_file = PathBuf::new();
    config_file.push(matches.value_of_os("db").unwrap());

    let pwsd = matches.value_of("password").unwrap();
    let pws = password::parse_password_source(&pwsd).unwrap();
    let pw = password::evaluate_password_source(pws).unwrap();

    let config_exists = config_file.is_file();

    // the only command that's valid if the DB doesn't exist is init
    if let ("init", Some(subargs)) = matches.subcommand() {
        if config_exists {
            io::stderr().write(config_file.as_os_str().as_bytes()).unwrap();
            io::stderr().write(b" already exists\n").unwrap();
            exit(1);
        }
        let cn = subargs.value_of("name").unwrap().to_string();
        let instance = server::SecretsServer::create(config_file, cn, pw).unwrap();
        // let fingerprint = instance.ssl_fingerprint().unwrap();
        let server_info = instance.get_peer_info().unwrap();
        println!("=== created server: ===\n{}", server_info.printable_report());
        return;
    }

    if !config_exists {
        io::stderr().write(config_file.as_os_str().as_bytes()).unwrap();
        io::stderr().write(b" not found. did you init?\n").unwrap();
        exit(1);
    }

    // everyone else needs the server set up
    let mut instance = server::SecretsServer::connect(config_file, pw).unwrap();

    match matches.subcommand() {
        ("server", Some(subargs)) => {
            let listen = subargs.value_of("listen").unwrap();
            listener::listen(instance, listen).unwrap()
        },
        ("server-info", _) => {
            let server_info = instance.get_peer_info().unwrap();

            println!("=== server info: ===\n{}", server_info.printable_report());

            // let fingerprint = instance.ssl_fingerprint().unwrap();
            // println!("ssl fingerprint: {}", fingerprint);
            // let cn = instance.ssl_cn().unwrap();
            // println!("ssl common name: {}", cn);
            // let (public_key, _) = instance.get_keys().unwrap();
            // println!("public key: {}", utils::hex(public_key.as_ref()));
            // let (public_sign, _) = instance.get_signs().unwrap();
            // println!("public sign: {}", utils::hex(public_sign.as_ref()));
        },
        ("accept-join", Some(subargs)) => {
            let filename = subargs.value_of("filename").unwrap();
            let mut payload = String::new();
            let mut file = File::open(filename).unwrap();
            file.read_to_string(&mut payload).unwrap();
            let jr = JoinRequest::from_pastable(payload.as_bytes()).unwrap();
            instance.accept_join(jr).unwrap();
        }
        _ => unreachable!()
    }
}
