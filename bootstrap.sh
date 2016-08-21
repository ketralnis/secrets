#!/bin/bash

# bootstrapper for Vagrant

# NOTE!! we install rust from curl|sh and libsodium from a non-distro PPA. This
# is intended for development. Use a trusted source of these packages in
# production!

set -ev

if ! [ -f /usr/lib/x86_64-linux-gnu/libsodium.so ]; then
    add-apt-repository -y ppa:chris-lea/libsodium
    apt-get -y update
    apt-get -y install libsodium-dev libsqlite3-dev openssl libssl-dev pkg-config gnupg
fi

# deal with a technicality with sudo -E
chmod 755 /root

if ! which cargo; then
    cd /home/vagrant
    curl -sf https://sh.rustup.rs > rustup.sh
    chmod u+x ./rustup.sh
    export CARGO_HOME=/usr/local
    export RUSTUP_HOME=/usr/local
    export RUSTUP_TOOLCHAIN=stable
    ./rustup.sh -y # >rustup.log 2>&1
    rustup default stable
    # tail rustup.log
fi

# build and install
if ! [ -f /usr/local/bin/secrets ]; then
    cd /home/vagrant/secrets
    sudo -u vagrant -EH -- /bin/sh -c "cargo clean"
    sudo -u vagrant -EH -- /bin/sh -c "cargo build --release"
    cargo install --root /usr/local
fi

# set up the server user
if ! id secrets-server; then
    adduser --disabled-password --gecos "" secrets-server
fi

# set up the server DB
if ! [ -f /home/secrets-server/secrets.db ]; then
    su - secrets-server -c "secrets-server -p pass: -d /home/secrets-server/secrets.db init --name $(hostname -f)"
fi

if ! [ -f /etc/init/secrets-server.conf ]; then
    # set up the upstart service
    cat >/etc/init/secrets-server.conf<<HERE
start on runlevel [2345]
stop on runlevel [06]
exec /usr/local/bin/secrets-server -p pass: -d /home/secrets-server/secrets.db server
HERE
fi

if ! pgrep -fl secrets-server; then
    service secrets-server start
    sleep 1 # give it a sec to start
fi

# set up and accept the vagrant user
sudo -u vagrant -EH -- /bin/sh -c "yes | secrets -p pass:password join -u vagrant -h $(hostname -f):4430 > /home/vagrant/vagrant.secrets-request"
sudo -u secrets-server -EH -- /bin/sh -c "yes | secrets-server -p pass: -d /home/secrets-server/secrets.db accept-join /home/vagrant/vagrant.secrets-request"

# create an example secret value
sudo -u vagrant -EH -- /bin/sh -c "echo 'shh dont tell noone' | secrets -p pass:password create --source=stdin sooper-sekrit"
sudo -u vagrant -EH -- /bin/sh -c "secrets -p pass:password list"
