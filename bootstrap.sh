#!/bin/bash

# bootstrapper for Vagrant

# NOTE!! we install rust from curl|sh and libsodium from a non-distro PPA. This
# is intended for development. Use a trusted source of these packages in
# production!

set -ev

add-apt-repository -y ppa:chris-lea/libsodium

apt-get -y update
apt-get -y install libsodium-dev libsqlite3-dev openssl libssl-dev pkg-config gnupg

# deal with a technicality with su -m
chmod 755 /root

cd /home/vagrant
curl -sf https://static.rust-lang.org/rustup.sh > rustup.sh
chmod u+x ./rustup.sh
./rustup.sh >rustup.log 2>&1
tail rustup.log

# build and install
cd /home/vagrant/secrets
su - vagrant -mc "cargo clean && cargo build --release"
cargo install --root /usr/local

# set up the server user
adduser --disabled-password --gecos "" secrets-server
# set up the server DB
su - secrets-server -c "secrets-server -p pass: -d /home/secrets-server/secrets.db init --name $(hostname -f)"

# set up the upstart service
cat >/etc/init/secrets-server.conf<<HERE
start on runlevel [2345]
stop on runlevel [06]
exec /usr/local/bin/secrets-server -p pass: -d /home/secrets-server/secrets.db server
HERE
service secrets-server start

# set up and accept the vagrant user
su - vagrant -mc "yes | secrets -p pass:password join -u vagrant -h $(hostname -f):4430 > /home/vagrant/vagrant.secrets-request"
su - secrets-server -mc "yes | secrets-server -p pass: -d /home/secrets-server/secrets.db accept-join /home/vagrant/vagrant.secrets-request"

# create an example secret value
su - vagrant -mc "echo 'dont tell noone' | secrets -p pass:password create --source=stdin sooper-sekrit"
su - vagrant -mc "secrets -p pass:password list"
