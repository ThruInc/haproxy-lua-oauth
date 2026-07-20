#!/usr/bin/env bash
#
# Run the jwtverify test suite with a bare Lua interpreter.
# No luarocks / busted / network access required. Works with Lua 5.4 and 5.5.
#
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LUA_BIN="${LUA:-}"
if [ -z "$LUA_BIN" ]; then
  for c in lua5.4 lua5.5 lua; do
    if command -v "$c" >/dev/null 2>&1; then LUA_BIN="$c"; break; fi
  done
fi
if [ -z "$LUA_BIN" ]; then
  echo "error: no lua interpreter found (tried lua5.4, lua5.5, lua)" >&2
  exit 127
fi

echo "Using: $("$LUA_BIN" -v 2>&1)"
exec "$LUA_BIN" "$DIR/jwtverify_test.lua"
