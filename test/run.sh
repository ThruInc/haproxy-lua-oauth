#!/usr/bin/env bash
#
# Run the jwtverify test suite under Lua 5.4 -- the version that ships in the
# HAProxy image in prod (and, therefore, on the devbox). No luarocks / busted /
# network access required.
#
# The suite loads lib/jwtverify.lua byte-for-byte, exactly as prod does. That
# file does not parse under Lua >= 5.5 (generic-for control vars became const),
# so this runner requires a 5.4 interpreter and refuses to "pass" under another
# version, which would only mask real parity drift.
#
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prefer an explicit 5.4 binary. Homebrew keeps it keg-only under opt/.
LUA_BIN="${LUA:-}"
if [ -z "$LUA_BIN" ]; then
  for c in lua5.4 /opt/homebrew/opt/lua@5.4/bin/lua5.4 /usr/local/opt/lua@5.4/bin/lua5.4 lua; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then LUA_BIN="$c"; break; fi
  done
fi
if [ -z "$LUA_BIN" ]; then
  echo "error: no lua interpreter found (need Lua 5.4, e.g. 'brew install lua@5.4')" >&2
  exit 127
fi

VER="$("$LUA_BIN" -v 2>&1)"
echo "Using: $VER"
case "$VER" in
  *"Lua 5.4"*) ;;
  *) echo "error: expected Lua 5.4 (prod parity); got: $VER" >&2
     echo "       set LUA=/path/to/lua5.4 or 'brew install lua@5.4'" >&2
     exit 1 ;;
esac

exec "$LUA_BIN" "$DIR/jwtverify_test.lua"
