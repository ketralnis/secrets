#!/bin/sh

if ! which fswatch > /dev/null; then
    echo fswatch not available &>2
    exit 1
fi

while true; do
    clear
    echo $(date) $CHANGED
    ./test.sh
    echo waiting for changes
    CHANGED="$(fswatch -rt1x --exclude 'tmp' src test.sh dev.sh)"
done