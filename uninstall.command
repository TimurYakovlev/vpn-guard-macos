#!/bin/sh
cd "$(dirname "$0")" || exit 1
printf 'Disable watcher and resume its recorded processes? Type YES: '
read -r answer
if [ "$answer" != YES ]; then exit 1; fi
sh ./control.sh uninstall
result=$?
printf '\nPress Enter to close.\n'
read -r unused
exit "$result"
