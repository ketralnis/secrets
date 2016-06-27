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
curl --insecure https://$(hostname):4430/api/info; echo ''

for new_user in dking florence; do
    echo creating user $new_user

    CLIENT="./target/debug/secrets-client -d ./tmp/client-$new_user.db -p pass:password_$new_user"

    yes | $CLIENT join -u $new_user -h $(hostname):4430 > tmp/$new_user.request
    cat tmp/$new_user.request
    sqlite3 tmp/$new_user.db .dump

    echo "checking if we're accepted (this should fail)"
    ! $CLIENT check-server

    echo "accepting $new_user"
    yes | $SERVER accept-join tmp/$new_user.request

    # should work now
    echo "checking that we're accepted (this should succeed)"
    $CLIENT check-server

    echo client successful
done

CLIENT1="./target/debug/secrets-client -d ./tmp/client-dking.db -p pass:password_dking"
CLIENT2="./target/debug/secrets-client -d ./tmp/client-florence.db -p pass:password_florence"

$CLIENT1 create twitter pass:twitterpass
$CLIENT1 info twitter
$CLIENT1 authorize twitter florence
$CLIENT1 info twitter

$CLIENT1 list --mine | grep twitter
! $CLIENT2 list --mine | grep twitter

$CLIENT1 list --all | grep twitter
$CLIENT2 list --all | grep twitter

$CLIENT2 get twitter | grep twitterpass

! $SERVER fire florence
$SERVER fire florence | grep -E "twitter"

$CLIENT1 rotate twitter pass:newtwitterpass1 --withhold florence
$CLIENT1 rotate twitter pass:newtwitterpass2 --only dking

echo hello | $CLIENT1 encrypt florence > tmp/encrypted.bydavid
$CLIENT2 decrypt < tmp/encrypted.bydavid | grep hello

$SERVER fire florence

! $CLIENT2 get twitter
