#!/bin/sh
cd "$(dirname "$0")" || exit 1
sh ./control.sh status
result=$?
printf '\nPress Enter to close.\n'
read -r unused
exit "$result"
