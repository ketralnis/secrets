Secrets is a system for safely storing and sharing passwords amongst a team

# Goals

1. Trustless. You don't have to trust the server. Users only need to trust each other.
2. End to end encryption. The server never sees the passwords in plaintext
3. Revocability. If everyone goes through Secrets, you have a good record of who knows what passwords. That means that your team can let someone go and know what password they have to rotate.
4. Rotation hygiene. Similar to revocability, you can easily rotate passwords on a schedule without disrupting everyone

See more in [DESIGN.md](DESIGN.md)

# Dependencies

* [libsodium](https://download.libsodium.org/doc/installation/)
* [openssl](https://www.openssl.org/)
* [sqlite](https://www.sqlite.org/)

# Example basic usage:

* `secrets create my-bank`: create a new service (you'll be prompted for the new password for it)
* `secrets get my-bank`: get the secret
* `secrets grant my-bank --grantee=federico`: give federico access to my-bank
* `secrets rotate my-bank --withhold=federico`: take my-bank away from federico by setting a new one (you'll be prompted for the new value)
* `secrets list --mine`: show what services you hold grants for

# Quickstart (vagrant)

The best way to try it out without committing to anything

* install [vagrant](https://www.vagrantup.com/) and [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
* `git clone https://github.com/ketralnis/secrets && cd secrets`
* `vagrant up`
* `vagrant ssh`
* `secrets get sooper-sekrit` (the default password is `password`)

# Quickstart (development)

The best way to develop on secrets

* Install libsodium, openssl, git, rust, and cargo
* Set it up:

```sh
# build it
git clone https://github.com/ketralnis/secrets && cd secrets
cargo test
cargo build
export PATH=$PATH:$(pwd)/target/debug

# set up the server
secrets-server -d ./server.db init -n $(hostname)
secrets-server -d ./server.db server &

# set up a client
secrets -d ./leeroy-jenkins.db join -u leeroy-jenkins -h $(hostname):4430 > leeroy-jenkins.request
secrets-server -d ./server.db accept-join leeroy-jenkins.request

# set up an example secret value...
secrets -d ./leeroy-jenkins.db create sooper-sekret
# ...and fetch it
secrets -d ./leeroy-jenkins.db get sooper-sekret
```

## cleanup

* `rm -i server.db ~/.secrets-client.db leeroy-jenkins.db leeroy-jenkins.request`