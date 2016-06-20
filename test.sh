#!/bin/sh

set -ev

rm -fr ./tmp
mkdir tmp

cargo test # in test mode
cargo build # in dev mode

export RUST_BACKTRACE=1
export RUST_LOG=debug

SERVER="./target/debug/secrets-server -d ./tmp/server.db"

$SERVER init -n $(hostname)
$SERVER info

$SERVER server &
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
curl --insecure https://$(hostname):4430/api/health; echo ''

for new_user in dking florence; do
    echo creating user $new_user

    CLIENT="./target/debug/secrets-client -d ./tmp/$new_user.db -p pass:password_$new_user"

    yes | $CLIENT request-join -u $new_user -h $(hostname):4430 > tmp/$new_user.request
    cat tmp/$new_user.request
    sqlite3 tmp/client.db .dump

    yes | $SERVER accept-join $new_user tmp/$new_user.request > tmp/$new_user.response
    cat tmp/$new_user.response

    yes | $CLIENT join $new_user tmp/$new_user.response
done

CLIENT1="./target/debug/secrets-client -d ./tmp/client-dking.db -p pass:password_dking"
CLIENT2="./target/debug/secrets-client -d ./tmp/client-florence.db -p pass:password_florence"

$CLIENT1 create twitter pass:twitterpass
$CLIENT1 authorize twitter florence

$CLIENT2 get twitter | grep twitterpass

$SERVER fire florence && false || true
$SERVER fire florence | grep -E "twitter"

$CLIENT1 rotate twitter pass:newtwitterpass1 --withhold florence
$CLIENT1 rotate twitter pass:newtwitterpass2 --only dking

echo hello | $CLIENT1 encrypt florence > tmp/encrypted.bydavid
$CLIENT2 decrypt < tmp/encrypted.bydavid | grep hello

$SERVER fire florence

$CLIENT2 get twitter && false || true
