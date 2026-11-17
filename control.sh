#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ "$(uname -s)" != Darwin ]; then
  echo 'This installer supports macOS only.' >&2
  exit 1
fi
if [ "$(id -u)" = 0 ]; then
  echo 'Run without sudo, as your normal macOS user.' >&2
  exit 1
fi
# A Finder session does not normally inherit the Homebrew PATH.
PATH="/opt/homebrew/bin:/usr/local/bin:/Library/Frameworks/Python.framework/Versions/Current/bin:$PATH"
export PATH
PYTHON=$(command -v python3 || true)
if [ -z "$PYTHON" ] || ! "$PYTHON" -c 'import sys; assert sys.version_info >= (3,10)' 2>/dev/null; then
  echo 'Install Python 3.10+ for macOS from https://www.python.org/downloads/macos/ and run again.' >&2
  exit 1
fi
exec "$PYTHON" vpn_guard.py "${1:-status}"
