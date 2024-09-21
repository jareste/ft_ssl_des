#!/bin/bash

compare_hashes() {
    local label="$1"
    local openssl_hash="$2"
    local ft_ssl_hash="$3"

    if [ "$openssl_hash" == "$ft_ssl_hash" ]; then
        echo "sha256 hashes match for $label."
    else
        echo "sha256 hashes do not match for $label."
        echo "OpenSSL: $openssl_hash"
        echo "ft_ssl:  $ft_ssl_hash"
    fi
}

if [ -p /dev/stdin ]; then
    input=$(cat)

    openssl_output=$(echo -n "$input" | openssl sha256)
    ft_ssl_output=$(echo -n "$input" | ./ft_ssl sha256)

    openssl_hash=$(echo "$openssl_output" | awk -F '= ' '{print $2}' | tr -d ' ')
    ft_ssl_hash=$(echo "$ft_ssl_output" | awk -F '= ' '{print $2}' | tr -d ' ')

    compare_hashes "piped input" "$openssl_hash" "$ft_ssl_hash"
fi

for FILE in "$@"; do
    if [ -f "$FILE" ]; then
        openssl_output=$(openssl sha256 "$FILE")
        ft_ssl_output=$(./ft_ssl sha256 "$FILE")

        openssl_hash=$(echo "$openssl_output" | awk -F '= ' '{print $2}' | tr -d ' ')
        ft_ssl_hash=$(echo "$ft_ssl_output" | awk -F '= ' '{print $2}' | tr -d ' ')

        compare_hashes "$FILE" "$openssl_hash" "$ft_ssl_hash"
    else
        echo "File not found: $FILE"
    fi
done
