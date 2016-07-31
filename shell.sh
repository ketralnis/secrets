#!/bin/sh

set -e

if ! [ -f ./tmp/server.db ]; then
    ./test.sh || true
fi

export RUSTBACKTRACE=1
export RUST_LOG="secrets=debug"
export server="./target/debug/secrets-server -d ./tmp/server.db"
export client="target/debug/secrets"
export david="$client --db=./tmp/client-david.db -p pass:password_david"
export CLIENT_DAVID="$david"
export florence="$client --db=./tmp/client-florence.db -p pass:password_florence"
export CLIENT_FLORENCE="$florence"

$server server &
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

echo entering shell
export PS1="(secrets)\$ $PS1"
echo "    " server: $server
echo "    " client: $client
echo "    " david: $david
echo "    " florence: $florence

bash --noprofile --norc