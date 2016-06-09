#!/bin/sh

set -ev
export RUST_BACKTRACE=1

cargo build

rm -fr ./tmp
mkdir tmp

CLIENT="./target/debug/secrets-client -d ./tmp/client.db -p pass:password"
SERVER="./target/debug/secrets-server -d ./tmp/server.db"

$SERVER init
sqlite3 tmp/server.db .dump

# openssl genrsa -out tmp/server.key 2048
openssl req -nodes -new -x509 -newkey rsa:2048 -sha256 -keyout tmp/ssl.key -out tmp/ssl.cert \
    -subj "/C=US/ST=CA/L=San Francisco/O=Me, Inc./OU=/CN=$(hostname)/emailAddress=root@$(hostname)"

$SERVER server --ssl-key=tmp/ssl.key --ssl-cert=tmp/ssl.cert &
SERVER_PID=$!
echo started server at $SERVER_PID

# kill it when we're done
trap "ps -p $SERVER_PID > /dev/null && kill $SERVER_PID" EXIT

# make sure it launched
sleep 0.5
if ! ps -p $SERVER_PID > /dev/null; then
    echo "server didn't start"
    exit 1
fi

echo checking http health
curl --insecure https://localhost:4430/api/health; echo ''

$CLIENT request-account -u dking -h localhost:4430 > tmp/dking.request
cat tmp/dking.request
sqlite3 tmp/client.db .dump

yes | $SERVER create-user -f tmp/dking.request

# $SERVER create-user dking -f tmp/dking.request

echo "mypassword" | $CLIENT create-service

#
# cargo run --bin secrets-server -- -d ./tmp/secrets.db init
# cargo run --bin secrets-server -- -d ./tmp/secrets.db create-user dking
