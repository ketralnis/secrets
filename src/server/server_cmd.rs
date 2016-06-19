use std::path::{PathBuf, Path};
use std::io;
use std::process::exit;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;

use env_logger;
use clap::{Arg, App, AppSettings, SubCommand};
use sodiumoxide;

use password;
use utils;
use server::server;
use server::listener;
use client::client_cmd::PASSWORD_SOURCE_HELP;

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
        .subcommand(SubCommand::with_name("info")
            .about("show info about the server"))
        .get_matches();

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
        let mut instance = server::SecretsServer::create(config_file, cn, pw).unwrap();
        let fingerprint = instance.ssl_fingerprint().unwrap();
        println!("created server with fingerprint {}", fingerprint);
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
        ("info", _) => {
            let fingerprint = instance.ssl_fingerprint().unwrap();
            println!("ssl fingerprint: {}", fingerprint);
            let cn = instance.cn().unwrap();
            println!("cn: {}", cn);
        }
        _ => unreachable!()
    }
}
