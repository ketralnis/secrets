use std::env;
use std::io::Write;
use std::io;
use std::path::PathBuf;
use std::process::exit;

use clap::{Arg, ArgGroup, App, AppSettings, SubCommand};
use env_logger;
use openssl::ssl::init as init_openssl;
use sodiumoxide;

use api::Grant;
use client::client;
use password;
use utils;

// TODO this renders like crap
// TODO move this
pub const PASSWORD_SOURCE_HELP: &'static str = "\
                                                Where to get the master password. Valid formats:\n\
                                                \tpass:password (a literal password)\n\
                                                \tenv:VARIABLE (an environment variable)\n\
                                                \tfile:filename (read from a file; beware of newlines!)\n\
                                                \tfd:number (read from a file descriptor)\n\
                                                \tprompt (you will be prompted)";

fn make_clap<'a, 'b>() -> App<'a, 'b> {
    App::new("secrets-client")
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
        .subcommand(SubCommand::with_name("echo-password")
            .about("for testing the password source system")
            .arg(Arg::with_name("source")
                .index(1)
                .takes_value(true)
                .required(true)
                .validator(password::validate_password_source)))
        .subcommand(SubCommand::with_name("join")
            .about("create a new account and request to join a server")
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
        .subcommand(SubCommand::with_name("check-server")
            .about("check that the server is up and that we can authenticate"))
        .subcommand(SubCommand::with_name("client-info")
            .about("show info about the client"))
        .subcommand(SubCommand::with_name("server-info")
            .about("show info about the server"))
        .subcommand(SubCommand::with_name("user")
            .about("print out some info about a service")
            .arg(Arg::with_name("username")
                .index(1)
                .takes_value(true)
                .required(true)
                .multiple(true)))
        .subcommand(SubCommand::with_name("info")
            .about("print out some info about a service")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true)
                .multiple(true)))
        .subcommand(SubCommand::with_name("grant-info")
            .about("print out some info about a particular grant")
            .arg(Arg::with_name("grant_name")
                .index(1)
                .takes_value(true)
                .required(true)
                .multiple(true)
                .validator(Grant::clap_validate_name)))
        .subcommand(SubCommand::with_name("get")
            .about("get the current secret value for a service")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true)
                .multiple(true)))
        .subcommand(SubCommand::with_name("grant")
            .about("grant someone access to an existing service")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("grantee")
                .index(2)
                .takes_value(true)
                .required(true)
                .multiple(true)))
        .subcommand(SubCommand::with_name("rotate")
            .about("change the secret for a service")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true)
                .multiple(true))
            .arg(Arg::with_name("source")
                .long("source")
                .help(PASSWORD_SOURCE_HELP)
                .takes_value(true)
                .default_value("prompt")
                .validator(password::validate_password_source))
            .arg(Arg::with_name("withhold")
                .long("withhold")
                .takes_value(true)
                .multiple(true))
            .arg(Arg::with_name("grant")
                .long("grant")
                .takes_value(true)
                .multiple(true))
            .arg(Arg::with_name("copy")
                .long("copy")
                .takes_value(false))
            .group(ArgGroup::with_name("rotation strategy")
                .args(&["withhold", "grant", "copy"])))
        .subcommand(SubCommand::with_name("edit")
            .about("shortcut to edit the secret for a service in a local editor")
            .arg(Arg::with_name("service_name")
                .index(1)
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("editor")
                .long("editor")
                .short("e")
                .takes_value(true)))
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
            .arg(Arg::with_name("grant")
                .long("grant")
                .takes_value(true)
                .multiple(true)))
        .subcommand(SubCommand::with_name("list")
            .about("list services")
            .arg(Arg::with_name("mine")
                .long("mine")
                .multiple(true)
                .help("services that I hold grants for"))
            .arg(Arg::with_name("all")
                .long("all")
                .help("all services"))
            .arg(Arg::with_name("grantee")
                .help("services that a given person holds grants for")
                .long("grantee")
                .multiple(true)
                .takes_value(true))
            .group(ArgGroup::with_name("for whom")
                .args(&["all", "mine", "grantee"])))
        .subcommand(SubCommand::with_name("grants")
            .about("list all grantees of a given service")
            .arg(Arg::with_name("service_name")
                .index(1)
                .help("the name of the service")
                .takes_value(true)
                .required(true)))
}

pub fn main() {
    let clapapp = make_clap();
    let matches = clapapp.get_matches();

    init_openssl();
    env_logger::init().unwrap();
    sodiumoxide::init();

    if let ("echo-password", Some(subargs)) = matches.subcommand() {
        let pwsd = subargs.value_of("source").unwrap().to_string();
        let pws = password::parse_password_source(&pwsd).unwrap();
        let pw = password::evaluate_password_source(pws, "to echo").unwrap();
        println!("{}", pw);
        exit(0);
    }

    // find or infer the location of .secrets-client.db
    if matches.value_of_os("db") == None && env::home_dir() == None {
        panic!("--db not specified and $HOME not set\n");
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
    let is_join = matches.subcommand_matches("join").is_some();
    if config_exists && is_join {
        panic!("{} already exists", config_file.to_str().unwrap());
    } else if !config_exists && !is_join {
        panic!("{} not found. did you join?", config_file.to_str().unwrap());
    }

    // every command needs a valid password to proceed
    let pwsd = matches.value_of("password").unwrap().to_string();
    let pws = password::parse_password_source(&pwsd).unwrap();
    let pw = password::evaluate_password_source(pws, "store password").unwrap();

    if let ("join", Some(subargs)) = matches.subcommand() {
        let username = subargs.value_of("username").unwrap().to_string();
        let host = subargs.value_of("host").unwrap().to_string();
        let client =
            client::SecretsClient::create(config_file, host, username, pw)
                .unwrap();
        let client_report =
            client.get_peer_info().unwrap().printable_report().unwrap();
        io::stderr()
            .write_all(format!("{}\n", client_report).as_bytes())
            .unwrap();
        let jr = client.join_request().unwrap();
        io::stderr()
            .write_all(b"Send this to your friendly local secrets admin:\n")
            .unwrap();
        io::stderr().flush().unwrap();
        let pastable = jr.to_pastable().unwrap();
        io::stdout().write_all(pastable.as_bytes()).unwrap();
        io::stdout().write_all(b"\n").unwrap();
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
            let grantees: Vec<String> = if subargs.is_present("grant") {
                subargs
                    .values_of("grant")
                    .unwrap()
                    .map(|w| w.to_owned())
                    .collect()
            } else {
                Vec::new()
            };
            let secret_source = subargs.value_of("source").unwrap();
            let secret_source = password::parse_password_source(secret_source)
                .unwrap();
            let secret_value = password::evaluate_password_source(
                secret_source,
                "secret data",
            ).unwrap();
            let secret_value = secret_value.as_bytes().to_owned();
            instance
                .create_service(service_name.to_owned(), secret_value, grantees)
                .unwrap()
        }
        ("client-info", Some(_)) => {
            let client_info = instance.get_peer_info().unwrap();
            println!("{}", client_info.printable_report().unwrap());
        }
        ("server-info", Some(_)) => {
            let server_info = instance.get_server_info().unwrap();
            println!("{}", server_info.printable_report().unwrap());
        }
        ("user", Some(subargs)) => {
            let usernames: Vec<String> = subargs
                .values_of("username")
                .unwrap()
                .map(|w| w.to_owned())
                .collect();
            for username in usernames {
                let user = instance.get_user(&username).unwrap();
                let peer_info = user.to_peer_info();
                println!("{}", peer_info.printable_report().unwrap());
            }
        }
        ("grant-info", Some(subargs)) => {
            let grant_names: Vec<String> = subargs
                .values_of("grant_name")
                .unwrap()
                .map(|w| w.to_owned())
                .collect();
            for grant_name in grant_names {
                let grant = instance.get_grant(&grant_name).unwrap();
                println!("{}", grant.printable_report());
            }
        }
        ("info", Some(subargs)) => {
            let service_names: Vec<String> = subargs
                .values_of("service_name")
                .unwrap()
                .map(|w| w.to_owned())
                .collect();
            for service_name in service_names {
                let service = instance.get_service(&service_name).unwrap();
                println!("{}", service.printable_report());
            }
        }
        ("get", Some(subargs)) => {
            let service_names: Vec<String> = subargs
                .values_of("service_name")
                .unwrap()
                .map(|s| s.to_owned())
                .collect();
            for service_name in service_names {
                let decrypted_grant =
                    instance.get_decrypted_grant(&service_name).unwrap();

                io::stdout().write_all(&decrypted_grant.plaintext).unwrap();
                io::stdout().write_all(b"\n").unwrap();
            }
        }
        ("grant", Some(subargs)) => {
            let service_name: String =
                subargs.value_of("service_name").unwrap().to_string();
            let grantees: Vec<String> = subargs
                .values_of("grantee")
                .unwrap()
                .map(|s| s.to_owned())
                .collect();

            instance.add_grants(service_name, grantees).unwrap();
        }
        ("rotate", Some(subargs)) => {
            // we can theoretically rotate multiple services at once, as long as
            // we hold a grant to all of them and they can all share the same
            // rotation strategy and value
            let service_names: Vec<String> = subargs
                .values_of("service_name")
                .unwrap()
                .map(|s| s.to_owned())
                .collect();

            let rotation_stategy = if !subargs
                .is_present("rotation strategy") ||
                subargs.is_present("copy")
            {
                client::RotationStrategy::Copy
            } else if let Some(whos) = subargs.values_of("withhold") {
                let whos = whos.map(|w| w.to_owned()).collect();
                client::RotationStrategy::Withhold(whos)
            } else if let Some(whos) = subargs.values_of("grant") {
                let whos = whos.map(|w| w.to_owned()).collect();
                client::RotationStrategy::Only(whos)
            } else {
                unreachable!()
            };

            let secret_source = subargs.value_of("source").unwrap();
            let secret_source = password::parse_password_source(secret_source)
                .unwrap();
            let secret_value = password::evaluate_password_source(
                secret_source,
                "secret value",
            ).unwrap();
            let secret_value = secret_value.as_bytes().to_owned();

            for service_name in service_names {
                instance
                    .rotate_service(
                        &service_name,
                        &rotation_stategy,
                        secret_value.clone(),
                    )
                    .unwrap();
            }
        }
        ("list", Some(subargs)) => {
            if !subargs.is_present("for whom") || subargs.is_present("all") {
                // list all services
                for service in instance.all_services().unwrap() {
                    println!("{}", service.name);
                }
            } else if subargs.is_present("mine") ||
                       subargs.is_present("grantee")
            {
                // list all services that a given user holds a grant for
                let grantee_names = if subargs.is_present("mine") {
                    vec![instance.username().unwrap()]
                } else if let Some(grantee_names) =
                    subargs.values_of("grantee")
                {
                    grantee_names.map(|s| s.to_owned()).collect()
                } else {
                    unreachable!()
                };

                for grantee_name in &grantee_names {
                    let grants =
                        instance.grants_for_grantee(grantee_name).unwrap();
                    for grant in grants {
                        if grantee_names.len() == 1 {
                            println!("{}", grant.service_name);
                        } else {
                            println!("{}", grant.key());
                        }
                    }
                }
            } else {
                unreachable!()
            }
        }
        ("grants", Some(subargs)) => {
            let service_names: Vec<String> = subargs
                .values_of("service_name")
                .unwrap()
                .map(|s| s.to_owned())
                .collect();
            for service_name in &service_names {
                let grants = instance.grants_for_service(service_name).unwrap();
                for grant in grants {
                    if service_names.len() == 1 {
                        println!("{}", grant.grantee);
                    } else {
                        println!("{}", grant.key());
                    }
                }
            }
        }
        ("edit", Some(subargs)) => {
            let service_name =
                subargs.value_of("service_name").unwrap().to_string();
            let decrypted_grant =
                instance.get_decrypted_grant(&service_name).unwrap();
            let editor = subargs.value_of("editor").map(|s| s.to_owned());
            let plaintext = decrypted_grant.plaintext;
            let new_value = password::edit(editor, &plaintext).unwrap();
            if !utils::constant_time_compare(&plaintext, &new_value) {
                instance
                    .rotate_service(
                        &service_name,
                        &client::RotationStrategy::Copy,
                        new_value,
                    )
                    .unwrap();
            }
        }

        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::make_clap;

    #[test]
    pub fn test_make_clap() {
        // a lot of clap's validation is done at runtime, so this test just
        // makes sure it creates okay
        make_clap();
    }
}
