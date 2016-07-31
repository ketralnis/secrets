#!/bin/sh

while true; do
    clear
    echo $(date) $CHANGED
    ./test.sh
    echo waiting for changes
    CHANGED="$(fswatch -rt1x --exclude 'tmp' src test.sh dev.sh)"
done