use std::env;
use std::io;
use std::process::exit;
use std::io::Write;
use std::path::PathBuf;
use std::os::unix::ffi::OsStrExt;

use env_logger;
use clap::{Arg, App, AppSettings, SubCommand};
use sodiumoxide;
use openssl::ssl::init as init_openssl;

use utils;
use password;
use client::client;
use common::SecretsContainer;

// TODO this renders like crap
// TODO move this
pub const PASSWORD_SOURCE_HELP: &'static str = "Where to get the master password. Valid formats:
   pass:password (a literal password)
   env:VARIABLE (an environment variable)
   file:filename (read from a file; beware of newlines)
   fd:number (read from a file descriptor)
   prompt (you will be prompted)
";

pub fn main() {
    let mut clapapp = App::new("secrets-client")
        .setting(AppSettings::SubcommandRequiredElseHelp)
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
        .subcommand(SubCommand::with_name("join")
            .arg(Arg::with_name("username")
                .short("u").long("username")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("host")
                .short("h").long("host")
                .validator(|h| utils::validate_host("host", &h))
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("check-server"))
        .subcommand(SubCommand::with_name("create")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("source")
                .index(2)
                .takes_value(true)
                .required(false)
                .default_value("prompt")
                .validator(password::validate_password_source))
            .arg(Arg::with_name("grants")
                .long("grants")
                .takes_value(true)));

    if cfg!(not(ndebug)) {
        clapapp = clapapp.subcommand(SubCommand::with_name("echo-password")
            .arg(Arg::with_name("source")
                .index(1)
                .takes_value(true)
                .required(true)
                .validator(password::validate_password_source)));
    }

    let matches = clapapp.get_matches();

    init_openssl();
    env_logger::init().unwrap();
    sodiumoxide::init();

    // a command for testing the password source system
    if let ("echo-password", Some(subargs)) = matches.subcommand() {
        let pwsd = subargs.value_of("source").unwrap().to_string();
        let pws = password::parse_password_source(&pwsd).unwrap();
        let pw = password::evaluate_password_source(pws).unwrap();
        println!("{}", pw);
        exit(0);
    }

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

    // the only command that's valid if the DB doesn't exist is join
    let config_exists = config_file.is_file();
    let is_create = matches.subcommand_matches("join").is_some();
    if config_exists && is_create {
        io::stderr().write(config_file.as_os_str().as_bytes()).unwrap();
        io::stderr().write(b" already exists\n").unwrap();
        exit(1);
    } else if !config_exists && !is_create {
        io::stderr().write(config_file.as_os_str().as_bytes()).unwrap();
        io::stderr().write(b" not found. did you join?\n").unwrap();
        exit(1);
    }

    // every command needs a valid password to proceed
    let pwsd = matches.value_of("password").unwrap().to_string();
    let pws = password::parse_password_source(&pwsd).unwrap();
    let pw = password::evaluate_password_source(pws).unwrap();

    if let ("join", Some(subargs)) = matches.subcommand() {
        let username = subargs.value_of("username").unwrap().to_string();
        let host = subargs.value_of("host").unwrap().to_string();
        let mut client = client::SecretsClient::create(config_file, host,
                                                       username, pw).unwrap();
        let request_payload = client.generate_join_request().unwrap();
        io::stderr().write("Send this to your friendly local secrets admin:\n".as_bytes()).unwrap();
        io::stdout().write(request_payload.as_bytes()).unwrap();
        io::stdout().write("\n".as_bytes()).unwrap();
        exit(0);
    }

    // otherwise they have a valid user already
    let instance = client::SecretsClient::connect(config_file, pw).unwrap();
    let username: String = instance.get_global("username").unwrap();

    if let ("check-server", Some(_)) = matches.subcommand() {
        instance.check_server().unwrap();
        exit(0);
    }

    match matches.subcommand() {
        ("create", Some(subargs)) => {
            println!("1");
            let service_name = subargs.value_of("service_name").unwrap();
            println!("2");
            let grantees = subargs.value_of("grants");
            println!("3");
            let secret_source = subargs.value_of("source").unwrap();
            println!("4");
            let secret_source = password::parse_password_source(secret_source).unwrap();
            println!("5");
            let secret_value = password::evaluate_password_source(secret_source);
            println!("6");
        }
        _ => unreachable!()
    }
}
