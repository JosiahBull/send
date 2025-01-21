#!/bin/bash

# Author: Josiah Bull <josiah.bull7@gmail.com>
# Date: 2025-01-21
# Description: Upload a file to the send server.
# Source: https://github.com/JosiahBull/send/

set -o errexit -o nounset -o pipefail

help_text="Usage: upload.sh [--expiry <expiry>] [--rename-file <rename-file>] --key <key> --domain <domain> <file-to-upload>"

# Parse the command line arguments
expiry="6h"
rename_file=""
key="$SEND_SSH_KEY" # default to the env var if possible
file_to_upload=""
domain="$SEND_DOMAIN" # default to the env var if possible
do_install=""

while [ $# -gt 0 ]; do
    case "$1" in
        --expiry)
            expiry="$2"
            shift
            ;;
        --rename-file)
            rename_file="$2"
            shift
            ;;
        --key)
            key="$2"
            shift
            ;;
        --domain)
            domain="$2"
            shift
            ;;
        --install)
            do_install="true"
            ;;
        *)
            file_to_upload="$1"
            ;;
    esac
    shift
done

function do_install {
    echo "Installing upload script to /usr/local/bin/send"
    curl https://raw.githubusercontent.com/JosiahBull/send/main/scripts/upload.sh > /usr/local/bin/send
    chmod +x /usr/local/bin/send
    echo "Installed upload script to /usr/local/bin/send"

    echo "Installing bash completion for send"
    curl https://raw.githubusercontent.com/JosiahBull/send/main/scripts/completions/send-completion.bash > /etc/bash_completion.d/send
    chmod +x /etc/bash_completion.d/send
    echo "Installed bash completion for send"

    # if zsh on system, install zsh completion
    zsh_present=$(command -v zsh)
    if [ -n "$zsh_present" ]; then
        echo "Installing zsh completion for send"
        curl https://raw.githubusercontent.com/JosiahBull/send/main/scripts/completions/_send > /usr/share/zsh/site-functions/_send
        chmod +x /usr/share/zsh/site-functions/_send
        echo "Installed zsh completion for send"
    fi

    # if fish on system, install fish completion
    fish_present=$(command -v fish)
    if [ -n "$fish_present" ]; then
        echo "Installing fish completion for send"
        curl https://raw.githubusercontent.com/JosiahBull/send/main/scripts/completions/send.fish > /usr/share/fish/vendor_completions.d/send.fish
        chmod +x /usr/share/fish/vendor_completions.d/send.fish
        echo "Installed fish completion for send"
    fi

    # Let the user know that they can set env vars to avoid passing them in
    echo "You can set the SEND_SSH_KEY and SEND_DOMAIN environment variables to avoid passing them in"
    echo "Installation complete"
}

if [ -n "$do_install" ]; then
    do_install
    exit 0
fi

if [ -z "$key" ] || [ -z "$file_to_upload" ]; then
    echo "$help_text" >&2
    exit 1
fi

if [ -z "$rename_file" ]; then
    rename_file=$(basename $file_to_upload)
fi

# If file does not exist, throw an error.
if [ ! -f "$file_to_upload" ]; then
    echo "Error: File does not exist: $file_to_upload" >&2
    exit 1
fi

# If the file is a directory, compress into zip
if [ -d "$file_to_upload" ]; then
    echo "Compressing directory into zip" >&2
    zip_file=$(mktemp).zip

    function cleanup {
        rm -f $zip_file
    }
    trap cleanup EXIT

    zip -r $zip_file $file_to_upload
    file_to_upload=$zip_file
    echo "Compressed directory into $zip_file" >&2

    # ensure rename_file has a .zip extension
    if [[ $rename_file != *.zip ]]; then
        rename_file="$rename_file.zip"
    fi
fi

# try to convert the expiry to seconds
expiry_secs=0
if [[ $expiry =~ ^[0-9]+[smhd]$ ]]; then
    unit=${expiry: -1}
    value=${expiry:0:${#expiry}-1}
    case $unit in
        s)
            expiry_secs=$value
            ;;
        m)
            expiry_secs=$((value * 60))
            ;;
        h)
            expiry_secs=$((value * 60 * 60))
            ;;
        d)
            expiry_secs=$((value * 60 * 60 * 24))
            ;;
    esac
fi

if [ $expiry_secs -eq 0 ]; then
    echo "Error: Invalid expiry: $expiry" >&2
    exit 1
fi

# Get the nonce from the server
nonce=$(curl -s -X GET http://$domain/api/v1/nonce)
nonce=$(echo -n $nonce | sed 's/^"\(.*\)"$/\1/')

# Generate the signature using our private key
signature=$(echo -n $nonce | base64 -d | ssh-keygen -Y sign -n file -f $key - | tr -d '\n')

# Encode the response as a JSON object
json="{\"nonce\":\"$nonce\",\"signature\":\"$signature\"}"

# Encode into base64
json=$(echo -n $json | base64)

# Send the request with the signature
response=$(curl -s \
    -w "%{http_code}" \
    --header "Authorization: SshSig $json" \
    --header "Content-Type: multipart/form-data" \
    -F "file_name=$rename_file" \
    -F "file_size=$(stat -c %s $file_to_upload)" \
    -F "expiry_secs=$expiry" \
    -F "file=@$file_to_upload" \
    -X POST \
    http://$domain/api/v1/upload
)
http_code=${response: -3}
response=${response:0:${#response}-3}

# If 401 or 403, then the signature was invalid
if [ "$http_code" -eq 401 ] || [ "$http_code" -eq 403 ]; then
    echo "Error: Invalid signature" >&2
    echo "Consider using a different key" >&2
    echo "response: $response" >&2
    exit 1
fi

if [ "$http_code" -ne 200 ]; then
    echo "Error: Received HTTP status code $http_code" >&2
    echo "response: $response" >&2
    exit 1
fi

# strip the leading and trailing " from the response
response=$(echo $response | sed 's/^"\(.*\)"$/\1/')
url="http://$domain/$response"

echo "$url"

# If the command "clipboard-copy" is available, copy the response to the clipboard
if command -v clipboard-copy &> /dev/null; then
    echo -n $url | clipboard-copy
    echo "URL copied to clipboard"
fi
