use std::path::{PathBuf, Path};
use std::io;
use std::process::exit;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;

use env_logger;
use clap::{Arg, App, AppSettings, SubCommand};
use sodiumoxide;

use utils;
use server_db;
use server;

pub fn main() {
    let matches = App::new("secrets-server")
        .arg(Arg::with_name("db")
            .short("d").long("db")
            .value_name("DB_FILE")
            .help("path to the secrets database file")
            .required(true)
            .takes_value(true))
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("init")
            .about("initialise the database"))
        .subcommand(SubCommand::with_name("server")
            .about("bring up the secrets server")
            .arg(Arg::with_name("listen")
                .short("l").long("listen")
                .takes_value(true)
                .default_value("0.0.0.0:4430")
                .validator(utils::validate_host))
            .arg(Arg::with_name("ssl-key")
                .short("k").long("ssl-key")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("ssl-cert")
                .short("c").long("ssl-cert")
                .takes_value(true)
                .required(true)))
        // .subcommand(SubCommand::with_name("create-user")
        //     .about("create new user")
        //     .arg(Arg::with_name("username")
        //         .index(1)
        //         .required(true))
        //     .arg(Arg::with_name("key")
        //         .help("path to user's public key")
        //         .short("k").long("key")
        //         .takes_value(true)
        //         .required(true)))
        // .subcommand(SubCommand::with_name("disable-user")
        //     .about("disable a user")
        //     .arg(Arg::with_name("username")
        //         .index(1)))
        // .subcommand(SubCommand::with_name("rekey-user")
        //     .about("change a user's public key")
        //     .arg(Arg::with_name("username")
        //         .index(1)
        //         .required(true))
        //     .arg(Arg::with_name("new-key")
        //         .help("path to user's new public key")
        //         .short("f")
        //         .takes_value(true)
        //         .required(true)))
        .get_matches();

    env_logger::init().unwrap();
    sodiumoxide::init();

    // the only command that's valid if the DB doesn't exist is init
    let mut config_file = PathBuf::new();
    config_file.push(matches.value_of_os("db").unwrap());

    let config_exists = config_file.is_file();
    let is_init = matches.subcommand_matches("init").is_some();
    if config_exists && is_init {
        io::stderr().write(config_file.as_os_str().as_bytes()).unwrap();
        io::stderr().write(b" already exists\n").unwrap();
        exit(1);
    } else if !config_exists && !is_init {
        io::stderr().write(config_file.as_os_str().as_bytes()).unwrap();
        io::stderr().write(b" not found. did you init?\n").unwrap();
        exit(1);
    }

    if let ("init", subargs) = matches.subcommand() {
        init_db(config_file);
        return;
    }

    // everyone else needs the server DB set up
    let db_conn = server_db::ServerDb::connect(config_file).unwrap();

    match matches.subcommand() {
        ("server", Some(subargs)) => {
            let ssl_key_path = subargs.value_of_os("ssl-key").unwrap();
            let ssl_cert_path = subargs.value_of_os("ssl-cert").unwrap();
            let listen = subargs.value_of("listen").unwrap();
            server::start_server(db_conn,
                                 &ssl_key_path, &ssl_cert_path,
                                 listen).unwrap()
        }
        _ => unreachable!()
    }
}

fn init_db<P: AsRef<Path>>(path: P) {
    server_db::ServerDb::create(path).unwrap();
}
