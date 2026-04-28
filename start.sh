#!/usr/bin/env bash

# Check root status immediately
if [ "$(id -u)" = "0" ] || [ -n "$SUDO_USER" ]; then
    echo "Error: This script must not be run as root or with sudo" >&2
    echo "Run as: ${USER:-your-username}" >&2
    exit 77 # 77 is commonly used for "permission denied" in scripts
fi

# Then check directory
if [ ! -d "$HOME/.SuperSploit" ]; then
    echo "Error: Directory $HOME/.SuperSploit does not exist" >&2
    exit 1
fi

python3 "$HOME/.SuperSploit/SuperSploit.py"