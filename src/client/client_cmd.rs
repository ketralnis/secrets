use std::env;
use std::io;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::exit;

use clap::{Arg, ArgGroup, App, AppSettings, SubCommand};
use env_logger;
use openssl::ssl::init as init_openssl;
use sodiumoxide;

use client::client;
use password;
use utils;

// TODO this renders like crap
// TODO move this
pub const PASSWORD_SOURCE_HELP: &'static str = "\
    Where to get the master password. Valid formats:
    pass:password (a literal password)
    env:VARIABLE (an environment variable)
    file:filename (read from a file; beware of newlines!)
    fd:number (read from a file descriptor)
    prompt (you will be prompted)";

pub fn main() {
    let clapapp = App::new("secrets-client")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg(Arg::with_name("db")
            .short("d")
            .long("--db")
            .value_name("FILENAME")
            .help("the path to the secrets-client config file")
            .takes_value(true))
        .arg(Arg::with_name("password")
            .short("p")
            .long("--password")
            .value_name("PASSWORD-SOURCE")
            .help(PASSWORD_SOURCE_HELP)
            .takes_value(true)
            .default_value("prompt")
            .validator(password::validate_password_source))
        .subcommand(SubCommand::with_name("join")
            .arg(Arg::with_name("username")
                .short("u")
                .long("username")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("host")
                .short("h")
                .long("host")
                .validator(|h| utils::validate_host("host", &h))
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("check-server"))
        .subcommand(SubCommand::with_name("client-info")
            .about("show info about the client"))
        .subcommand(SubCommand::with_name("server-info")
            .about("show info about the server"))
        .subcommand(SubCommand::with_name("info")
            .about("print out some info about a service")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("get")
            .about("get the current secret value for a service")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("grant")
            .about("grant someone access to an existing service")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("grantees")
                .index(2)
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("rotate")
            .about("change the secret for a service")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("source")
                .long("source")
                .help(PASSWORD_SOURCE_HELP)
                .takes_value(true)
                .default_value("prompt")
                .validator(password::validate_password_source))
            .arg(Arg::with_name("withhold")
                .long("withhold")
                .takes_value(true))
            .arg(Arg::with_name("only")
                .long("only")
                .takes_value(true))
            .arg(Arg::with_name("copy")
                .long("copy")
                .takes_value(false))
            .group(ArgGroup::with_name("rotation strategy")
                .args(&["withhold", "only", "copy"])))
        .subcommand(SubCommand::with_name("create")
            .about("create a new service")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("source")
                .long("source")
                .takes_value(true)
                .required(false)
                .default_value("prompt")
                .validator(password::validate_password_source))
            .arg(Arg::with_name("grants")
                .long("grants")
                .takes_value(true)))
        .subcommand(SubCommand::with_name("echo-password")
            .arg(Arg::with_name("source")
                .index(1)
                .takes_value(true)
                .required(true)
                .hidden(true)
                .validator(password::validate_password_source)));

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
        }
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
        let client =
            client::SecretsClient::create(config_file, host, username, pw)
                .unwrap();
        let client_report =
            client.get_peer_info().unwrap().printable_report().unwrap();
        io::stderr()
            .write(format!("=== created client info: ===\n{}\n",
                           client_report)
                .as_bytes())
            .unwrap();
        let jr = client.join_request().unwrap();
        io::stderr()
            .write("Send this to your friendly local secrets admin:\n"
                .as_bytes())
            .unwrap();
        let pastable = jr.to_pastable().unwrap();
        io::stdout().write(pastable.as_bytes()).unwrap();
        io::stdout().write("\n".as_bytes()).unwrap();
        exit(0);
    }

    // otherwise they have a valid user already
    let mut instance = client::SecretsClient::connect(config_file, pw).unwrap();

    if let ("check-server", Some(_)) = matches.subcommand() {
        instance.check_server().unwrap();
        exit(0);
    }

    match matches.subcommand() {
        ("create", Some(subargs)) => {
            let service_name = subargs.value_of("service_name").unwrap();
            let grantees = subargs.value_of("grants")
                .map(|v| {
                    v.split(",").map(|v| v.to_owned()).collect::<Vec<String>>()
                })
                .unwrap_or(Vec::new());
            let secret_source = subargs.value_of("source").unwrap();
            let secret_source = password::parse_password_source(secret_source)
                .unwrap();
            let secret_value =
                password::evaluate_password_source(secret_source).unwrap();
            let secret_value = secret_value.as_bytes().to_owned();
            instance.create_service(service_name.to_owned(),
                                    secret_value,
                                    grantees)
                .unwrap();
            exit(0);
        }
        ("client-info", Some(_)) => {
            let client_info = instance.get_peer_info().unwrap();
            println!("=== client info: ===\n{}",
                     client_info.printable_report().unwrap());
        }
        ("server-info", Some(_)) => {
            let server_info = instance.get_server_info().unwrap();
            println!("=== server info: ===\n{}",
                     server_info.printable_report().unwrap());
        }
        ("info", Some(subargs)) => {
            let service_name: String = subargs.value_of("service_name").unwrap().to_string();
            let service = instance.get_service(service_name).unwrap();
            println!("\
                name: {}\n\
                created: {}\n\
                modified: {}\n\
                creator: {}\n\
                modified by: {}\
                ",
                service.name,
                utils::pretty_date(service.created),
                utils::pretty_date(service.modified),
                service.creator,
                service.modified_by,
            );
        }
        ("get", Some(subargs)) => {
            let service_name: String = subargs.value_of("service_name").unwrap().to_string();
            let decrypted_grant = instance.get_grant(&service_name).unwrap();

            io::stdout().write(&decrypted_grant.plaintext).unwrap();
            io::stdout().write(b"\n").unwrap();
        },
        ("grant", Some(subargs)) => {
            let service_name: String = subargs.value_of("service_name").unwrap().to_string();
            let grantees: String = subargs.value_of("grantees").unwrap().to_string();
            let grantees: Vec<String> = grantees.split(",").map(|s|s.to_owned()).collect();

            instance.add_grants(service_name, grantees).unwrap();
        },
        ("rotate", Some(subargs)) => {
            let service_name: String = subargs.value_of("service_name").unwrap().to_string();

            let rotation_stategy =
                if !subargs.is_present("rotation strategy") || subargs.is_present("copy") {
                    client::RotationStrategy::Copy
                } else if let Some(who) = subargs.value_of("withhold") {
                    let who = who.split(",").map(|s| s.to_owned()).collect();
                    client::RotationStrategy::Withhold(who)
                } else if let Some(who) = subargs.value_of("only") {
                    let who = who.split(",").map(|s| s.to_owned()).collect();
                    client::RotationStrategy::Only(who)
                } else {
                    unreachable!()
                };

            let secret_source = subargs.value_of("source").unwrap();
            let secret_source = password::parse_password_source(secret_source)
                .unwrap();
            let secret_value =
                password::evaluate_password_source(secret_source).unwrap();
            let secret_value = secret_value.as_bytes().to_owned();

            instance.rotate_service(service_name, rotation_stategy, secret_value).unwrap();
        },

        _ => unreachable!(),
    }
}
