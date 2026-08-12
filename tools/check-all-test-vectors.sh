#!/bin/bash

set -e

cd `dirname "$0"`

jar=$(ls target/boku-http-auth-tools-*-main.jar 2>/dev/null | head -1)
if [ -z "$jar" ]; then
    echo "ERROR: no tools jar found in target/ — run 'mvn package' first" >&2
    exit 1
fi
check="java -jar $jar check"

for file in test-vectors/*; do
    echo -n "$file: "
    $check -quiet $file
done

