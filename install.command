#!/bin/sh
cd "$(dirname "$0")" || exit 1
sh ./control.sh install
result=$?
printf '\nPress Enter to close.\n'
read -r unused
exit "$result"
