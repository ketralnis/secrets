use std::cmp::{Ord, Eq};
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::fs::File;
use std::hash::Hash;
use std::io::Read;
use std::path::PathBuf;
use std::process::exit;

use clap::{Arg, App, AppSettings, SubCommand};
use env_logger;
use openssl::ssl::init as init_openssl;
use sodiumoxide;

use api::{Grant, JoinRequest};
use client::client_cmd::PASSWORD_SOURCE_HELP;
use common::SecretsError;
use password;
use server::listener;
use server::server;
use utils;

fn make_clap<'a, 'b>() -> App<'a, 'b> {
    App::new("secrets-server")
        .arg(Arg::with_name("db")
            .short("d")
            .long("db")
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
                .short("n")
                .long("name")
                .help("the hostname that others will use to contact me")
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("server")
            .about("bring up the secrets server")
            .arg(Arg::with_name("listen")
                .short("l")
                .long("listen")
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
        .subcommand(SubCommand::with_name("fire")
            .about("fire (disable) a user, succeeding only if they have no outstanding grants")
            .arg(Arg::with_name("firee")
                .index(1)
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("force")
                .long("force")
                .short("f")
                .help("disable this user, even though they have outstanding grants")))
}

pub fn main() {
    let matches = make_clap().get_matches();

    init_openssl();
    env_logger::init().unwrap();
    sodiumoxide::init();

    let mut config_file = PathBuf::new();
    config_file.push(matches.value_of_os("db").unwrap());

    let pwsd = matches.value_of("password").unwrap();
    let pws = password::parse_password_source(&pwsd).unwrap();
    let pw = password::evaluate_password_source(pws, "store password").unwrap();

    let config_exists = config_file.is_file();

    // the only command that's valid if the DB doesn't exist is init
    if let ("init", Some(subargs)) = matches.subcommand() {
        if config_exists {
            panic!("{} already exists", config_file.to_str().unwrap());
        }
        let cn = subargs.value_of("name").unwrap().to_string();
        let instance = server::SecretsServer::create(config_file, cn, pw)
            .unwrap();
        // let fingerprint = instance.ssl_fingerprint().unwrap();
        let server_info = instance.get_peer_info().unwrap();
        println!("{}", server_info.printable_report().unwrap());
        return;
    }

    if !config_exists {
        panic!("{} not found. did you init?", config_file.to_str().unwrap());
    }

    // everyone else needs the server set up
    let mut instance = server::SecretsServer::connect(config_file, pw).unwrap();

    match matches.subcommand() {
        ("server", Some(subargs)) => {
            let listen = subargs.value_of("listen").unwrap();
            listener::listen(instance, listen).unwrap()
        }
        ("server-info", _) => {
            let server_info = instance.get_peer_info().unwrap();
            println!("{}", server_info.printable_report().unwrap());
        }
        ("accept-join", Some(subargs)) => {
            let filename = subargs.value_of("filename").unwrap();
            let mut payload = String::new();
            let mut file = File::open(filename).unwrap();
            file.read_to_string(&mut payload).unwrap();
            let jr = JoinRequest::from_pastable(payload.as_bytes()).unwrap();
            instance.accept_join(jr).unwrap();
        }
        ("fire", Some(subargs)) => {
            let firee = subargs.value_of("firee").unwrap().to_string();
            let force = subargs.is_present("force");
            match instance.fire_user(&firee, false).unwrap() {
                server::FireResult::Success => {
                    info!("disabled {}", firee);
                }
                server::FireResult::OutstandingGrants {grants} => {
                    print_plan_firing(&instance, &firee, grants).unwrap();

                    if force {
                        warn!("forcibly firing {} with outstanding grants!",
                              firee);
                        let success = instance.fire_user(&firee, true).unwrap();
                        if success != server::FireResult::Success {
                            panic!("forcible firing still failed?");
                        }
                        info!("disabled {}", firee);
                        exit(0);
                    }

                    exit(1);
                }
            }
        }
        _ => unreachable!(),
    }
}

fn print_plan_firing(instance: &server::SecretsServer,
                     firee: &String,
                     grants: Vec<Grant>) -> Result<(), SecretsError> {
    let user = try!(instance.get_user(firee));

    if user.disabled.is_some() {
        println!("{} is disabled but they still hold some grants. Here's a proposed plan:",
                 firee);
    } else {
        println!("Can't fire {} because they hold some grants. Here's a proposed plan:",
                 firee);
    };

    let mut service_knowers = HashMap::new();
    for grant in grants {
        let other_knowers = try!(instance.get_grants_for_service(&grant.service_name))
            .iter()
            .filter(|g| g.grantee != (*firee))
            .map(|g| g.grantee.clone())
            .collect();
        service_knowers.insert(grant.service_name, other_knowers);
    }

    let firing_plan = plan_firing(&service_knowers);

    for (knower, known_services) in &firing_plan {
        let service_list: Vec<String> = known_services.iter()
            .map(|s| (*s).to_owned())
            .collect();

        if let &Some(knower) = knower {
            println!("{} should run:\n\
                \tsecrets rotate {} --withhold={}",
                knower,
                service_list.join(","),
                firee,
            )
        } else {
            println!("!!! These services have nobody else that knows them:");
            for service_name in &service_list {
                println!("\t{}", service_name)
            }
        }
    }

    return Ok(());
}

/// When we're trying to fire someone, we'll need to run around and find other
/// people that possess a grant to each service the firee holds so that we can
/// rotate them. This function tries to minimise the number of people required
/// to rotate every service
fn plan_firing<'a, S, U>(known_by: &'a HashMap<S, Vec<U>>)
                         -> HashMap<Option<&'a U>, Vec<&'a S>>
                         where S: Hash + Ord,
                               U: Hash + Eq,
                         {
    // uses a naive greedy set covering algorithm

    let mut ret: HashMap<Option<&U>, Vec<&S>> = HashMap::new();

    let mut to_know: BinaryHeap<&S> = BinaryHeap::new();
    let mut knowers: HashMap<&U, Vec<&S>> = HashMap::new();

    // keep track of what every one knows
    for (service, usernames) in known_by.iter() {
        to_know.push(service);
        for username in usernames {
            let vec = knowers.entry(username).or_insert_with(|| vec![]);
            (*vec).push(service);
        }
    }

    while let Some(next_service) = to_know.pop() {
        if let Some(service_knowers) = known_by.get(next_service) {
            // for this service, find the person that knows the most things in
            // general
            let best_knower = service_knowers.iter().max_by_key(|user|
                    match knowers.get(user) {
                        Some(x) => x.len(),
                        None => 0
                    }
            );

            if let Some(best) = best_knower {
                let vec = ret.entry(Some(best)).or_insert_with(|| vec![]);
                (*vec).push(next_service);
            } else {
                // nobody knows this
                let vec = ret.entry(None).or_insert_with(|| vec![]);
                (*vec).push(next_service);
            }
        } else {
            unreachable!()
        }
    }

    return ret;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{make_clap, plan_firing};

    #[test]
    pub fn test_make_clap() {
        // a lot of clap's validation is done at runtime, so this test just
        // makes sure it creates okay
        make_clap();
    }

    #[test]
    pub fn test_plan_firing() {
        let mut map = HashMap::new();
        map.insert("twitter", vec!["david", "florence"]);
        map.insert("reddit", vec!["david", "bob"]);
        map.insert("google", vec!["david", "florence"]);
        map.insert("dogpile", vec!["david", "frederico"]);
        map.insert("yahoo", vec!["florence"]);
        map.insert("digg", vec!["frank"]);
        map.insert("hn", vec![]);

        let mut optimal_plan = HashMap::new();
        optimal_plan.insert(None, vec!["hn"]);
        optimal_plan.insert(Some("david"), vec!["dogpile", "google", "twitter", "reddit"]);
        optimal_plan.insert(Some("florence"), vec!["yahoo"]);
        optimal_plan.insert(Some("frank"), vec!["digg"]);

        let firing_plan = plan_firing(&map);
        let mut firing_plan_human: Vec<(Option<String>, Vec<String>)> = firing_plan
            .iter()
            .map(|(k, v)| {
                let k = k.map(|k_| (*k_).to_string());
                let mut v: Vec<String> = v.iter()
                    .map(|v_| (*v_).to_string())
                    .collect();
                v.sort();
                (k, v)
            })
            .collect();
        firing_plan_human.sort();

        let mut optimal_plan_human: Vec<(Option<String>, Vec<String>)> = optimal_plan
            .iter()
            .map(|(k, v)| {
                let k = k.map(|k_| k_.to_string());
                let mut v: Vec<String> = v.iter()
                    .map(|v_| v_.to_string())
                    .collect();
                v.sort();
                (k, v)
            })
            .collect();
        optimal_plan_human.sort();

        assert_eq!(firing_plan_human, optimal_plan_human);
    }
}
