#!/bin/bash

set -e

cd `dirname "$0"`

check="java -jar target/boku-http-auth-tools-1.2-main.jar check"

for file in test-vectors/*; do
    echo -n "$file: "
    $check -quiet $file
done

