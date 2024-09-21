#!/bin/bash

compare_base64() {
    local label="$1"
    local openssl_output="$2"
    local ft_ssl_output="$3"

    # Use cmp to safely compare binary data and avoid null byte warnings
    if cmp -s "$openssl_output" "$ft_ssl_output"; then
        echo "Base64 outputs match for $label."
    else
        echo "Base64 outputs do not match for $label."
        echo "Check files: OpenSSL ($openssl_output), ft_ssl ($ft_ssl_output)"
    fi
}

run_test() {
    local FILE="$1"

    # Create temporary files for comparison
    openssl_encoded=$(mktemp)
    ft_ssl_encoded=$(mktemp)
    openssl_decoded=$(mktemp)
    ft_ssl_decoded=$(mktemp)

    # Encode using OpenSSL and ft_ssl, saving output to temporary files
    openssl base64 -in "$FILE" > "$openssl_encoded" 2>/dev/null
    ./ft_ssl base64 -i "$FILE" > "$ft_ssl_encoded" 2>/dev/null

    # Decode using both tools, saving the decoded results to temporary files
    openssl base64 -d -in "$openssl_encoded" > "$openssl_decoded" 2>/dev/null
    ./ft_ssl base64 -d -i "$openssl_encoded" > "$ft_ssl_decoded" 2>/dev/null

    # Compare encoding
    compare_base64 "$FILE encoding" "$openssl_encoded" "$ft_ssl_encoded"

    # Compare decoding of OpenSSL encoded content
    compare_base64 "$FILE OpenSSL decoding" "$openssl_decoded" "$ft_ssl_decoded"

    # Clean up temporary files
    rm -f "$openssl_encoded" "$ft_ssl_encoded" "$openssl_decoded" "$ft_ssl_decoded"
}

# Check for piped input
if [ -p /dev/stdin ]; then
    input=$(cat)

    # Create temporary files
    openssl_encoded=$(mktemp)
    ft_ssl_encoded=$(mktemp)
    openssl_decoded=$(mktemp)
    ft_ssl_decoded=$(mktemp)

    # Base64 encoding using OpenSSL and ft_ssl
    echo -n "$input" | openssl base64 > "$openssl_encoded" 2>/dev/null
    echo -n "$input" | ./ft_ssl base64 > "$ft_ssl_encoded" 2>/dev/null

    # Base64 decoding using OpenSSL and ft_ssl
    openssl base64 -d -in "$openssl_encoded" > "$openssl_decoded" 2>/dev/null
    ./ft_ssl base64 -d -i "$ft_ssl_encoded" > "$ft_ssl_decoded" 2>/dev/null

    compare_base64 "piped input encoding" "$openssl_encoded" "$ft_ssl_encoded"

    compare_base64 "piped input decoding" "$openssl_decoded" "$ft_ssl_decoded"

    # Clean up temporary files
    rm -f "$openssl_encoded" "$ft_ssl_encoded" "$openssl_decoded" "$ft_ssl_decoded"
fi

# Loop through the file arguments and run tests
for FILE in "$@"; do
    if [ -f "$FILE" ]; then
        run_test "$FILE" &
    else
        echo "File not found: $FILE"
    fi
done

# Wait for all background jobs to finish
wait
