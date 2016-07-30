#!/bin/sh

set -v

while true; do
    clear
    date
    ./test.sh
    echo waiting for changes
    fswatch -rt1x --exclude 'tmp' src test.sh dev.sh
done