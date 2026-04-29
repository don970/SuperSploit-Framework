#!/usr/bin/env bash
DEVMODE=false


# ==============================================================================
# SuperSploit Launcher Script
# This script verifies the environment is safe and properly configured before
# launching the main Python application.
# ==============================================================================

# Security Check: Ensure the script is NOT run as root or via sudo.
# Running user-level scripts as root can cause severe file permission issues.
if [ "$(id -u)" = "0" ] || [ -n "$SUDO_USER" ]; then
    # Output error messages directly to standard error (stderr) using >&2
    echo "Error: This script must not be run as root or with sudo" >&2
    # Use bash parameter expansion to suggest the current user, falling back to "your-username"
    echo "Run as: ${USER:-your-username}" >&2
    # Exit code 77 is conventionally used for "permission denied" or "insufficient privileges"
    exit 77
fi


# Installation Check: Verify that the SuperSploit directory exists in the user's home folder.
if [ ! -d "$HOME/.SuperSploit" ]; then
    if [ ! $DEVMODE ]; then
      echo "Error: Directory $HOME/.SuperSploit does not exist" >&2
      exit 1
    else
      # run the program from the source directory this
      echo "Running from source directory. This is not the intended way to run the program. development mode  is on"
      python3 "source/main.py"
      exit
    fi
fi

# Launch: Execute the main application logic using the Python 3 interpreter.
# The script is located within the hidden .SuperSploit directory in the user's home.
python3 "$HOME/.SuperSploit/source/main.py"
