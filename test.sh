#!/bin/sh

set -ev

rm -fr ./tmp
mkdir tmp

export RUST_BACKTRACE=1

cargo test # also builds it

export RUST_LOG="secrets=debug"

SERVER="./target/debug/secrets-server -d ./tmp/server.db"

$SERVER init -n $(hostname)
sqlite3 ./tmp/server.db .dump
$SERVER server-info

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
curl --insecure https://$(hostname):4430/api/server; echo ''

for new_user in dking florence; do
    echo creating user $new_user

    CLIENT="./target/debug/secrets -d ./tmp/client-${new_user}.db -p pass:password_${new_user}"

    yes | $CLIENT join -u $new_user -h $(hostname):4430 > tmp/$new_user.request
    cat tmp/$new_user.request
    sqlite3 "tmp/client-${new_user}.db" .dump

    $CLIENT client-info
    $CLIENT server-info

    echo "checking if we're accepted (this should fail)"
    ! $CLIENT check-server

    echo "accepting $new_user"
    yes | $SERVER accept-join tmp/$new_user.request

    # should work now
    echo "checking that we're accepted (this should succeed)"
    $CLIENT check-server

    echo client successful
done

CLIENT_DAVID="./target/debug/secrets -d ./tmp/client-dking.db -p pass:password_dking"
CLIENT_FLORENCE="./target/debug/secrets -d ./tmp/client-florence.db -p pass:password_florence"

$CLIENT_DAVID create twitter --source=pass:twitterpass --grants=dking
$CLIENT_DAVID info twitter
$CLIENT_DAVID info twitter | grep dking
$CLIENT_DAVID get twitter
$CLIENT_DAVID get twitter | grep twitterpass

$CLIENT_DAVID grant twitter florence
$CLIENT_DAVID grant twitter florence,dking # dking is implied

yes | $CLIENT_DAVID rotate twitter --source=pass:newtwitterpass1 --withhold florence
$CLIENT_DAVID get twitter
! $CLIENT_FLORENCE get twitter
yes | $CLIENT_FLORENCE rotate twitter --source=pass:newtwitterpass2 --only florence
! $CLIENT_DAVID get twitter
$CLIENT_FLORENCE get twitter
yes | $CLIENT_DAVID rotate twitter --source=pass:newtwitterpass3 --only dking
$CLIENT_DAVID get twitter
! $CLIENT_FLORENCE get twitter

$CLIENT_DAVID list --mine | grep twitter
! $CLIENT_FLORENCE list --mine | grep twitter

$CLIENT_DAVID list | grep twitter
$CLIENT_DAVID list --all | grep twitter
$CLIENT_FLORENCE list --all | grep twitter

$CLIENT_FLORENCE list --grantee=dking | grep '^twitter'
$CLIENT_FLORENCE list --grantee=dking,florence | grep twitter::

$CLIENT_DAVID grants twitter | grep florence
$CLIENT_DAVID grants twitter | grep dking

$CLIENT_DAVID user-info florence | grep twitter
$CLIENT_DAVID user-info dking | grep twitter

EDITOR=/bin/true $CLIENT_DAVID edit twitter

$CLIENT_FLORENCE get twitter | grep twitterpass

! $SERVER fire florence
$SERVER fire florence 2>&1 | grep -E "twitter"
$SERVER fire florence

! $CLIENT_FLORENCE get twitter

# tell me what services are in bus trouble
$CLIENT_DAVID bus-factor
$CLIENT_DAVID bus-factor twitter

# some installs may want there to be a special user that knows all of the
# secrets for administrative reasons. this prints out all secrets not held by
# the provided admin user
$CLIENT_DAVID admin-check dking

echo hello | $CLIENT_DAVID encrypt florence > tmp/encrypted.bydavid
$CLIENT_FLORENCE decrypt < tmp/encrypted.bydavid | grep hello
