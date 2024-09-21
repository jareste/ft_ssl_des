#!/bin/bash

DEFAULT_FILES=(resources/*)

if [ "$#" -eq 0 ]; then
    FILES=("${DEFAULT_FILES[@]}")
else
    FILES=("$@")
fi

run_checks() {
    local files=("$@")
    
    echo "Running BLAKE2s checks..."
    ./checkers/checker_blake2s.sh "${files[@]}"
    
    echo "Running MD5 checks..."
    ./checkers/checker_md5.sh "${files[@]}"
    
    echo "Running SHA256 checks..."
    ./checkers/checker_sha256.sh "${files[@]}"
    
    echo "Running WHIRLPOOL checks..."
    ./checkers/checker_whirlpool.sh "${files[@]}"

    echo "Running base64 ENCRYPT checks..."
    ./checkers/checker_base64.sh "${files[@]}"
}

run_checks "${FILES[@]}"
