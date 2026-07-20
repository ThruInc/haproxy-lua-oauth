--
-- Dependency-free test suite for lib/jwtverify.lua
--
-- This loads and exercises the REAL lib/jwtverify.lua (no copy-pasted logic).
-- The HAProxy Lua runtime (`core`, `txn`) and the OpenSSL / json / base64
-- modules are stubbed with pure-Lua fakes so the file can run under a bare
-- `lua` interpreter with no luarocks / busted / network access.
--
-- Run with:  lua test/jwtverify_test.lua   (or: test/run.sh)
--

-- Path to the file under test, resolved relative to this test file so the
-- suite works regardless of the current working directory.
local THIS = arg and arg[0] or "test/jwtverify_test.lua"
local TEST_DIR = THIS:match("^(.*)[/\\][^/\\]*$") or "."
local JWTVERIFY_PATH = TEST_DIR .. "/../lib/jwtverify.lua"

--------------------------------------------------------------------------------
-- Tiny test harness
--------------------------------------------------------------------------------
local passed, failed = 0, 0
local function check(cond, name)
  if cond then
    passed = passed + 1
    print("  ok   - " .. name)
  else
    failed = failed + 1
    print("  FAIL - " .. name)
  end
end
local function section(name) print("\n== " .. name .. " ==") end

--------------------------------------------------------------------------------
-- Pure-Lua base64url (round-trips with jwtverify's base64.decode usage)
--------------------------------------------------------------------------------
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64encode(data)
  local out = {}
  for i = 1, #data, 3 do
    local a, b, c = data:byte(i, i + 2)
    local n = a * 0x10000 + (b or 0) * 0x100 + (c or 0)
    local i1 = math.floor(n / 0x40000) % 0x40
    local i2 = math.floor(n / 0x1000) % 0x40
    local i3 = math.floor(n / 0x40) % 0x40
    local i4 = n % 0x40
    out[#out + 1] = B64:sub(i1 + 1, i1 + 1)
    out[#out + 1] = B64:sub(i2 + 1, i2 + 1)
    out[#out + 1] = b and B64:sub(i3 + 1, i3 + 1) or "="
    out[#out + 1] = c and B64:sub(i4 + 1, i4 + 1) or "="
  end
  return table.concat(out)
end
local DEC = {}
for i = 1, #B64 do DEC[B64:sub(i, i)] = i - 1 end
local function b64decode(s)
  s = s:gsub("[-]", "+"):gsub("[_]", "/"):gsub("%s", "")
  local pad = (4 - (#s % 4)) % 4
  s = s .. string.rep("=", pad)
  local out = {}
  for i = 1, #s, 4 do
    local c1, c2, c3, c4 = s:sub(i, i), s:sub(i + 1, i + 1), s:sub(i + 2, i + 2), s:sub(i + 3, i + 3)
    local n = (DEC[c1] or 0) * 0x40000 + (DEC[c2] or 0) * 0x1000
    if c3 ~= "=" then n = n + (DEC[c3] or 0) * 0x40 end
    if c4 ~= "=" then n = n + (DEC[c4] or 0) end
    out[#out + 1] = string.char(math.floor(n / 0x10000) % 0x100)
    if c3 ~= "=" then out[#out + 1] = string.char(math.floor(n / 0x100) % 0x100) end
    if c4 ~= "=" then out[#out + 1] = string.char(n % 0x100) end
  end
  return table.concat(out)
end
-- URL-safe, unpadded (matches JWT / the repo's base64.lua encode())
local function b64url(data)
  return (b64encode(data):gsub("=+$", ""):gsub("[+]", "-"):gsub("[/]", "_"))
end

--------------------------------------------------------------------------------
-- Minimal JSON encode/decode (sufficient for JWT header/payload objects)
--------------------------------------------------------------------------------
local function jsonEncode(v)
  local t = type(v)
  if v == nil then
    return "null"
  elseif t == "boolean" then
    return tostring(v)
  elseif t == "number" then
    return tostring(v)
  elseif t == "string" then
    return '"' .. v:gsub("\\", "\\\\"):gsub('"', '\\"') .. '"'
  elseif t == "table" then
    if v[1] ~= nil or next(v) == nil then -- array (or empty)
      local parts = {}
      for _, item in ipairs(v) do parts[#parts + 1] = jsonEncode(item) end
      return "[" .. table.concat(parts, ",") .. "]"
    else
      local parts = {}
      for k, val in pairs(v) do
        parts[#parts + 1] = jsonEncode(tostring(k)) .. ":" .. jsonEncode(val)
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
  end
  error("jsonEncode: unsupported type " .. t)
end

local function jsonDecode(str)
  local pos = 1
  local parseValue
  local function skipWs()
    local _, e = str:find("^%s*", pos)
    if e then pos = e + 1 end
  end
  local function parseString()
    pos = pos + 1 -- opening quote
    local buf = {}
    while pos <= #str do
      local c = str:sub(pos, pos)
      if c == '"' then
        pos = pos + 1
        return table.concat(buf)
      elseif c == "\\" then
        local nxt = str:sub(pos + 1, pos + 1)
        local map = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", n = "\n", t = "\t", r = "\r", b = "\b", f = "\f" }
        buf[#buf + 1] = map[nxt] or nxt
        pos = pos + 2
      else
        buf[#buf + 1] = c
        pos = pos + 1
      end
    end
    error("jsonDecode: unterminated string")
  end
  local function parseNumber()
    local s, e = str:find("^%-?%d+%.?%d*[eE]?[%+%-]?%d*", pos)
    local num = tonumber(str:sub(s, e))
    pos = e + 1
    return num
  end
  local function parseObject()
    pos = pos + 1 -- {
    local obj = {}
    skipWs()
    if str:sub(pos, pos) == "}" then pos = pos + 1; return obj end
    while true do
      skipWs()
      local key = parseString()
      skipWs()
      pos = pos + 1 -- colon
      obj[key] = parseValue()
      skipWs()
      local c = str:sub(pos, pos)
      pos = pos + 1
      if c == "}" then break end
      -- else comma; loop
    end
    return obj
  end
  local function parseArray()
    pos = pos + 1 -- [
    local arr = {}
    skipWs()
    if str:sub(pos, pos) == "]" then pos = pos + 1; return arr end
    while true do
      arr[#arr + 1] = parseValue()
      skipWs()
      local c = str:sub(pos, pos)
      pos = pos + 1
      if c == "]" then break end
      -- else comma; loop
    end
    return arr
  end
  parseValue = function()
    skipWs()
    local c = str:sub(pos, pos)
    if c == "{" then return parseObject()
    elseif c == "[" then return parseArray()
    elseif c == '"' then return parseString()
    elseif c == "t" then pos = pos + 4; return true
    elseif c == "f" then pos = pos + 5; return false
    elseif c == "n" then pos = pos + 4; return nil
    else return parseNumber() end
  end
  return parseValue()
end

--------------------------------------------------------------------------------
-- Shared fake state (verify-call counter, alert counter, clock)
--------------------------------------------------------------------------------
local state = { verifyCount = 0, alertCount = 0, now = 1000000 }

--------------------------------------------------------------------------------
-- package.preload stubs (installed once; jwtverify require()s these by name)
--------------------------------------------------------------------------------
package.preload["json"] = function()
  return { decode = jsonDecode, encode = jsonEncode }
end
package.preload["base64"] = function()
  return { encode = b64url, decode = b64decode }
end
package.preload["openssl.pkey"] = function()
  return {
    -- pkey.new(pem): fake parse. Any PEM containing "BADPEM" raises, mimicking
    -- an unparseable key. Otherwise returns a key object whose :verify() is
    -- true iff the (decoded) signature bytes equal "VALIDSIG".
    new = function(pem)
      if type(pem) == "string" and pem:find("BADPEM") then
        error("fake openssl: unable to parse PEM")
      end
      return {
        verify = function(_, signature, _digest)
          state.verifyCount = state.verifyCount + 1
          return signature == "VALIDSIG"
        end,
      }
    end,
  }
end
package.preload["openssl.digest"] = function()
  return {
    new = function(_algo)
      return { updated = "", update = function(self, data) self.updated = self.updated .. data end }
    end,
  }
end
package.preload["openssl.x509"] = function() return {} end
package.preload["openssl.hmac"] = function()
  return {
    new = function(_secret, _algo)
      return { final = function(_, data) return "hmac(" .. data .. ")" end }
    end,
  }
end

--------------------------------------------------------------------------------
-- Fake HAProxy `core` runtime + os.getenv control
--------------------------------------------------------------------------------
local captured = { init = nil, action = nil }
local ENV = {} -- controllable OAUTH_* environment

local realGetenv = os.getenv
os.getenv = function(name)
  if ENV[name] ~= nil then return ENV[name] end
  -- Fall through to real env for anything the test does not control.
  return realGetenv(name)
end

-- HAProxy's core.tokenize splits on ANY character in the separator set and
-- never yields empty tokens (so "Bearer a.b.c" on " ." -> 4 fields).
local function tokenize(s, seps)
  local res, set, cur = {}, {}, ""
  for i = 1, #seps do set[seps:sub(i, i)] = true end
  for i = 1, #s do
    local c = s:sub(i, i)
    if set[c] then
      if #cur > 0 then res[#res + 1] = cur; cur = "" end
    else
      cur = cur .. c
    end
  end
  if #cur > 0 then res[#res + 1] = cur end
  return res
end

_G.core = {
  Debug = function(_) end,
  Alert = function(_) state.alertCount = state.alertCount + 1 end,
  tokenize = tokenize,
  now = function() return { sec = state.now } end,
  register_init = function(fn) captured.init = fn end,
  register_action = function(_name, _evts, fn, _arity) captured.action = fn end,
}

--------------------------------------------------------------------------------
-- Load the REAL lib/jwtverify.lua into a fresh module instance.
--
-- Each call re-reads and re-load()s the source, giving a fresh module-local
-- verifiedCache and re-capturing the init/action closures. `cfg` is installed
-- as the global `config` before load so we exercise the file's own env/key
-- plumbing via the captured init function.
--
-- Runs under the same Lua that ships in the HAProxy image (Lua 5.4). We do NOT
-- rewrite the source: the test must load lib/jwtverify.lua byte-for-byte as
-- prod does. (Note: Lua >= 5.5 makes generic-for control variables const and
-- would reject line 58 of jwtverify.lua at parse time -- but prod/devbox pin
-- 5.4, so run this suite with lua5.4, not a stray newer interpreter.)
--------------------------------------------------------------------------------
local function loadModule(cfg)
  local f = assert(io.open(JWTVERIFY_PATH, "r"))
  local src = f:read("*a")
  f:close()

  captured.init, captured.action = nil, nil
  _G.config = cfg

  local chunk = assert(load(src, "@jwtverify.lua"))
  chunk() -- runs the file: registers init + action
  assert(captured.action, "jwtverify did not register an action")
  assert(captured.init, "jwtverify did not register an init")
  return captured.init, captured.action
end

--------------------------------------------------------------------------------
-- Fake txn factory
--------------------------------------------------------------------------------
local function makeTxn(authHeader)
  local txn = { vars = {} }
  txn.set_var = function(self, name, val) self.vars[name] = val end
  txn.sf = { req_hdr = function(_, _hdr) return authHeader end }
  return txn
end

--------------------------------------------------------------------------------
-- Token builder
--------------------------------------------------------------------------------
local function makeToken(header, payload, sigPlain)
  local h = b64url(jsonEncode(header))
  local p = b64url(jsonEncode(payload))
  local s = b64url(sigPlain)
  return "Bearer " .. h .. "." .. p .. "." .. s
end

local ISSUER = "https://issuer.example.com"
local AUDIENCE = "my-api"
local RS256 = { alg = "RS256" }

-- Standard config: exercises init env-plumbing (issuer/audience from OAUTH_*).
local function baseEnv()
  ENV = {
    OAUTH_ISSUER = ISSUER,
    OAUTH_AUDIENCE = AUDIENCE,
    OAUTH_KEY_PATHS = nil,
    OAUTH_HMAC_SECRET = nil,
    OAUTH_DEBUG = nil,
  }
end

-- Fresh module + run init, with one good public key.
local function freshVerifier()
  baseEnv()
  local init, action = loadModule({ debug = false, publicKeys = { "GOODPEM" } })
  init()
  return action
end

--------------------------------------------------------------------------------
-- Test cases
--------------------------------------------------------------------------------

-- 1. Valid token authorizes and populates payload variables.
section("1. valid token authorizes")
do
  local action = freshVerifier()
  local tok = makeToken(RS256, { iss = ISSUER, aud = AUDIENCE, exp = state.now + 3600 }, "VALIDSIG")
  local txn = makeTxn(tok)
  action(txn)
  check(txn.vars["txn.authorized"] == true, "authorized == true")
  check(txn.vars["txn.oauth.iss"] == ISSUER, "txn.oauth.iss set from payload")
  check(txn.vars["txn.oauth.aud"] == AUDIENCE, "txn.oauth.aud set from payload")
end

-- 2. Repeat of same header hits the cache: signature verify is NOT re-run,
--    and the payload variables are repopulated identically.
section("2. cache hit skips signature verify")
do
  local action = freshVerifier()
  local tok = makeToken(RS256, { iss = ISSUER, aud = AUDIENCE, exp = state.now + 3600 }, "VALIDSIG")

  local before = state.verifyCount
  local txn1 = makeTxn(tok)
  action(txn1)
  local afterFirst = state.verifyCount
  check(afterFirst == before + 1, "first call performs signature verify")
  check(txn1.vars["txn.authorized"] == true, "first call authorized")

  local txn2 = makeTxn(tok)
  action(txn2)
  check(state.verifyCount == afterFirst, "second (cached) call does NOT verify again")
  check(txn2.vars["txn.authorized"] == true, "cached call authorized")
  check(txn2.vars["txn.oauth.iss"] == ISSUER, "cached call repopulates payload vars")
end

-- 3. Tampered token (different bytes -> cache miss) is verified and rejected.
section("3. tampered token: cache miss, verify attempted, denied")
do
  local action = freshVerifier()
  -- Signature decodes to something other than "VALIDSIG" -> fake verify fails.
  local tok = makeToken(RS256, { iss = ISSUER, aud = AUDIENCE, exp = state.now + 3600 }, "TAMPERED")
  local before = state.verifyCount
  local txn = makeTxn(tok)
  action(txn)
  check(state.verifyCount == before + 1, "signature verify WAS attempted (cache miss)")
  check(txn.vars["txn.authorized"] == false, "authorized == false")
end

-- 4a. Expired token is denied.
-- 4b. A token cached while valid is re-verified (and denied) once expired.
section("4. expiry: denied, and cached-then-expired re-runs full path")
do
  local action = freshVerifier()

  -- 4a
  local expiredTok = makeToken(RS256, { iss = ISSUER, aud = AUDIENCE, exp = state.now - 10 }, "VALIDSIG")
  local txnE = makeTxn(expiredTok)
  action(txnE)
  check(txnE.vars["txn.authorized"] == false, "already-expired token denied")

  -- 4b: cache while valid, then advance the clock past exp.
  local exp = state.now + 100
  local tok = makeToken(RS256, { iss = ISSUER, aud = AUDIENCE, exp = exp }, "VALIDSIG")
  local v0 = state.verifyCount
  action(makeTxn(tok)) -- caches it
  check(state.verifyCount == v0 + 1, "initial verify while valid")

  state.now = exp + 1 -- token now expired
  local v1 = state.verifyCount
  local txnX = makeTxn(tok)
  action(txnX)
  check(state.verifyCount == v1 + 1, "expired cache entry falls through to full verification")
  check(txnX.vars["txn.authorized"] == false, "expired-after-cache token denied")
  state.now = 1000000 -- restore clock
end

-- 5. Issuer / audience mismatch: denied AND not cached (verify re-runs each time).
section("5. issuer/audience mismatch: denied and not cached")
do
  local action = freshVerifier()

  local badIss = makeToken(RS256, { iss = "https://evil.example", aud = AUDIENCE, exp = state.now + 3600 }, "VALIDSIG")
  local v0 = state.verifyCount
  action(makeTxn(badIss))
  local v1 = state.verifyCount
  check(v1 == v0 + 1, "issuer mismatch: verify attempted")
  action(makeTxn(badIss)) -- same header again
  check(state.verifyCount == v1 + 1, "issuer mismatch: NOT cached (verify re-runs)")

  local badAud = makeToken(RS256, { iss = ISSUER, aud = "someone-else", exp = state.now + 3600 }, "VALIDSIG")
  local txn = makeTxn(badAud)
  action(txn)
  check(txn.vars["txn.authorized"] == false, "audience mismatch denied")
  local v2 = state.verifyCount
  action(makeTxn(badAud))
  check(state.verifyCount == v2 + 1, "audience mismatch: NOT cached (verify re-runs)")
end

-- 6. Cache bound: fill past VERIFIED_CACHE_MAX (8192) without error; entries
--    still authorize. Behavioural bound test (the cap is a file-local).
section("6. cache bound: fill past 8192 entries")
do
  local action = freshVerifier()
  local far = state.now + 1000000
  local n = 8193
  for i = 1, n do
    local tok = makeToken(RS256, { iss = ISSUER, aud = AUDIENCE, exp = far, n = i }, "VALIDSIG")
    local txn = makeTxn(tok)
    action(txn)
    if txn.vars["txn.authorized"] ~= true then
      check(false, "entry " .. i .. " authorized while filling cache")
      break
    end
  end
  check(true, "filled " .. n .. " entries with no error")

  -- A fresh valid token still authorizes after the cap was crossed.
  local tok = makeToken(RS256, { iss = ISSUER, aud = AUDIENCE, exp = far, n = "post" }, "VALIDSIG")
  local txn = makeTxn(tok)
  action(txn)
  check(txn.vars["txn.authorized"] == true, "still authorizes after cache bound reached")
end

-- 7. init fail-fast on unparseable keys.
section("7. init: fail-fast when all keys bad, tolerate partial failure")
do
  -- 7a: all keys bad -> init errors and alerts.
  baseEnv()
  local init = loadModule({ debug = false, publicKeys = { "BADPEM" } })
  local alerts0 = state.alertCount
  local ok, err = pcall(init)
  check(not ok, "init errors when ALL public keys are unparseable")
  check(state.alertCount > alerts0, "init alerts on the unparseable key")
  check(type(err) == "string" and err:find("aborting startup") ~= nil, "error message mentions aborting startup")

  -- 7b: one good, one bad -> init succeeds, still alerts once.
  baseEnv()
  local init2 = loadModule({ debug = false, publicKeys = { "GOODPEM", "BADPEM" } })
  local alerts1 = state.alertCount
  local ok2 = pcall(init2)
  check(ok2, "init does NOT error when at least one key parses")
  check(state.alertCount == alerts1 + 1, "init alerts exactly once for the one bad key")
  check(#_G.config.parsedKeys == 1, "one key parsed successfully")
end

--------------------------------------------------------------------------------
print(string.format("\n%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
