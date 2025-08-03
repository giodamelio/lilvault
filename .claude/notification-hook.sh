#!/usr/bin/env nix-shell
#!nix-shell -i bash -p jq libnotify

# Parse JSON from stdin and extract the message
MESSAGE=$(cat | jq -r '.message // "Claude notification"')

# Send the notification with the extracted message
notify-send 'LilVault - Claude Notification' "$MESSAGE"
