use std::env;
use std::io;
use std::process::exit;
use std::io::Write;
use std::path::PathBuf;
use std::os::unix::ffi::OsStrExt;

use env_logger;
use clap::{Arg, App, AppSettings, SubCommand};
use sodiumoxide;

use utils;
use password;
use client;

// TODO this renders like crap
const PASSWORD_SOURCE_HELP: &'static str = "Where to get the master password. Valid formats:
   pass:password (a literal password)
   env:VARIABLE (an environment variable)
   file:filename (read from a file; beware of newlines)
   fd:number (read from a file descriptor)
   prompt (you will be prompted)
";

pub fn main() {
    let matches = App::new("secrets-client")
        .arg(Arg::with_name("db")
            .short("d").long("--db")
            .value_name("FILENAME")
            .help("the path to the secrets-client config file")
            .takes_value(true))
        .arg(Arg::with_name("password")
             .short("p").long("--password")
             .value_name("PASSWORD-SOURCE")
             .help(PASSWORD_SOURCE_HELP)
             .takes_value(true)
             .default_value("prompt")
             .validator(password::validate_password_source))
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("request-account")
            .arg(Arg::with_name("username")
                .short("u").long("username")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("host")
                .short("h").long("host")
                .validator(utils::validate_host)
                .takes_value(true)
                .required(true)))
        .get_matches();

    env_logger::init().unwrap();
    sodiumoxide::init();

    // find or infer the location of .secrets-client.db
    if matches.value_of_os("db") == None && env::home_dir() == None {
        io::stderr().write(b"--db not specified and $HOME not set\n").unwrap();
        exit(1);
    }

    let config_file = match matches.value_of_os("db") {
        Some(x) => {
            let mut buf = PathBuf::new();
            buf.push(x);
            buf
        },
        None => {
            let home_dir = env::home_dir().unwrap();
            home_dir.join(".secrets-client.db")
        }
    };

    // the only command that's valid if the DB doesn't exist is request-account
    let config_exists = config_file.is_file();
    let is_create = matches.subcommand_matches("request-account").is_some();
    if config_exists && is_create {
        io::stderr().write(config_file.as_os_str().as_bytes()).unwrap();
        io::stderr().write(b" already exists\n").unwrap();
        exit(1);
    } else if !config_exists && !is_create {
        io::stderr().write(config_file.as_os_str().as_bytes()).unwrap();
        io::stderr().write(b" not found. did you request-account?\n").unwrap();
        exit(1);
    }

    // every command needs a valid password to proceed
    let pwsd = matches.value_of("password").unwrap().to_string();
    let pws = password::parse_password_source(pwsd).unwrap();
    let pw = password::evaluate_password_source(pws).unwrap();

    if let ("request-account", Some(subargs)) = matches.subcommand() {
        let username = subargs.value_of("username").unwrap().to_string();
        let host = subargs.value_of("host").unwrap().to_string();
        client::SecretsClient::create(config_file, host,
                                      username, pw).unwrap();
    }

    match matches.subcommand() {
        // ("request-account", Some(subargs)) => {
        //     let username = subargs.value_of("username").unwrap().to_string();
        //     let host = subargs.value_of("host").unwrap().to_string();
        //     create_config(config_file, username, host)
        // }
        _ => unreachable!()
    }
}


// fn create_config<P: AsRef<Path>>(config_file: P, username: String, host: String) {
//     // boostraps all of our config
//     let (public_key, private_key) = keys::create_key();
//     let conn = client_conn::ClientConn::new(host.to_owned());
//     let db = client_db::create_db(config_file, username, host);
//     // TODO create and print request
// }
//
