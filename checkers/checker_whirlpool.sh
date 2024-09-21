#!/bin/bash

compare_hashes() {
    local label="$1"
    local rhash_output="$2"
    local ft_ssl_output="$3"

    if [ "$rhash_output" == "$ft_ssl_output" ]; then
        echo "Whirlpool hashes match for $label."
    else
        echo "Whirlpool hashes do not match for $label."
        echo "rhash:   $rhash_output"
        echo "ft_ssl:  $ft_ssl_output"
    fi
}

if [ -p /dev/stdin ]; then
    echo "rhash does not support stdin input."
fi

for FILE in "$@"; do
    if [ -f "$FILE" ]; then
        rhash_output=$(rhash \--whirlpool "$FILE" | awk '{print $1}')
        ft_ssl_output=$(./ft_ssl whirlpool "$FILE" | awk -F '= ' '{print $2}' | tr -d ' ')

        compare_hashes "$FILE" "$rhash_output" "$ft_ssl_output"
    else
        echo "File not found: $FILE"
    fi
done
