--
-- JWT Validation implementation for HAProxy Lua host
--
-- Copyright (c) 2019. Adis Nezirovic <anezirovic@haproxy.com>
-- Copyright (c) 2019. Baptiste Assmann <bassmann@haproxy.com>
-- Copyright (c) 2019. Nick Ramirez <nramirez@haproxy.com>
-- Copyright (c) 2019. HAProxy Technologies LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- Use HAProxy 'lua-load' to load optional configuration file which
-- should contain config table.
-- Default/fallback config
if not config then
  config = {
      debug = false,
      publicKeys = {},
      issuer = nil,
      audience = nil,
      hmacSecret = nil,
      keyPaths = nil
  }
end

-- search these paths for *.lua and *.so files on CentOS/RHEL
package.path = package.path .. ';/usr/local/share/lua/5.4/?.lua'
package.cpath = package.cpath .. ';/usr/local/lib/lua/5.4/?.so;/usr/local/lib/lua/5.4/?/?.so'

local json   = require 'json'
local base64 = require 'base64'
local openssl = {
  pkey = require 'openssl.pkey',
  digest = require 'openssl.digest',
  x509 = require 'openssl.x509',
  hmac = require 'openssl.hmac'
}

local function log(msg)
  if config.debug then
      core.Debug(tostring(msg))
  end
end

-- Denial reasons and cache flushes log unconditionally: with debug off (the
-- default) the proxy must still record *why* a request was rejected.
local function warn(msg)
  core.Warning(tostring(msg))
end

local function dump(o)
  if type(o) == 'table' then
     local s = '{ '
     for k,v in pairs(o) do
        if type(k) ~= 'number' then k = '"'..k..'"' end
        s = s .. '['..k..'] = ' .. dump(v) .. ','
     end
     return s .. '} '
  else
     return tostring(o)
  end
end

-- Loops through array to find the given string.
-- items: array of strings
-- test_str: string to search for
local function contains(items, test_str)
  for _,item in pairs(items) do

    -- strip whitespace
    item = item:gsub("%s+", "")
    test_str = test_str:gsub("%s+", "")

    if item == test_str then
      return true
    end
  end

  return false
end

local function readAll(file)
  log("Reading file " .. file)
  local f = assert(io.open(file, "rb"))
  local content = f:read("*all")
  f:close()
  return content
end

local function decodeJwt(authorizationHeader)
  local headerFields = core.tokenize(authorizationHeader, " .")

  if #headerFields ~= 4 then
      warn("Improperly formated Authorization header. Should be 'Bearer' followed by 3 token sections.")
      return nil
  end

  if headerFields[1] ~= 'Bearer' then
      warn("Improperly formated Authorization header. Missing 'Bearer' property.")
      return nil
  end

  local token = {}
  token.header = headerFields[2]
  token.headerdecoded = json.decode(base64.decode(token.header))

  token.payload = headerFields[3]
  token.payloaddecoded = json.decode(base64.decode(token.payload))

  token.signature = headerFields[4]
  token.signaturedecoded = base64.decode(token.signature)

  -- Guard the dump() calls: Lua evaluates arguments eagerly, so without this
  -- the recursive dump() + string concat ran on every request even when
  -- debug logging was disabled.
  if config.debug then
    log('Decoded JWT header: ' .. dump(token.headerdecoded))
    log('Decoded JWT payload: ' .. dump(token.payloaddecoded))
  end

  return token
end

local function algorithmIsValid(token)
  if token.headerdecoded.alg == nil then
      warn("No 'alg' provided in JWT header.")
      return false
  elseif token.headerdecoded.alg ~= 'HS256' and  token.headerdecoded.alg ~= 'HS512' and token.headerdecoded.alg ~= 'RS256' then
      warn("HS256, HS512 and RS256 supported. Incorrect alg in JWT: " .. token.headerdecoded.alg)
      return false
  end

  return true
end

local function rs256SignatureIsValid(token, parsedKeys)
  local digest = openssl.digest.new('SHA256')
  digest:update(token.header .. '.' .. token.payload)

  for _, vkey in ipairs(parsedKeys) do
    if vkey:verify(token.signaturedecoded, digest) then
      return true
    end
  end

  return false
end

local function hs256SignatureIsValid(token, secret)
  local hmac = openssl.hmac.new(secret, 'SHA256')
  local checksum = hmac:final(token.header .. '.' .. token.payload)
  return checksum == token.signaturedecoded
end

local function hs512SignatureIsValid(token, secret)
  local hmac = openssl.hmac.new(secret, 'SHA512')
  local checksum = hmac:final(token.header .. '.' .. token.payload)
  return checksum == token.signaturedecoded
end

local function expirationIsValid(token)
  return os.difftime(token.payloaddecoded.exp, core.now().sec) > 0
end

local function issuerIsValid(token, expectedIssuer)
  return token.payloaddecoded.iss == expectedIssuer
end

-- Checks if the audience in the token is listed in the
-- OAUTH_AUDIENCE environment variable. Both the token audience
-- and the environment variable can contain multiple audience values, 
-- separated by commas. Each value will be checked.
local function audienceIsValid(token, expectedAudienceParam)
  
  -- Convert OAUTH_AUDIENCE environment variable to a table,
  -- even if it contains only one value
  local expectedAudiences = expectedAudienceParam
  if type(expectedAudiences) == "string" then
    -- split multiple values using a space as the delimiter
    expectedAudiences = core.tokenize(expectedAudienceParam, " ")
  end

  -- Convert 'aud' claim to a table, even if it contains only one value
  local receivedAudiences = token.payloaddecoded.aud
  if type(token.payloaddecoded.aud) == "string" then
    receivedAudiences ={}
    receivedAudiences[1] = token.payloaddecoded.aud
  end

  for _, receivedAudience in ipairs(receivedAudiences) do
    if contains(expectedAudiences, receivedAudience) then
      return true
    end
  end

  return false
end

local function setVariablesFromPayload(txn, decodedPayload)
  for key, value in pairs(decodedPayload) do
    txn:set_var("txn.oauth." .. key, dump(value))
  end
end

-- In-process cache of successfully verified tokens.
--
-- Key   = the exact Authorization header value (full "Bearer <jwt>").
-- Value = { payload = <decoded claims>, exp = <numeric exp> }.
--
-- Only positive results are cached, keyed on the exact token bytes: a tampered
-- or forged token differs by at least one byte, so it can never collide with a
-- cached entry -- it misses the cache and goes through full signature
-- verification (and is rejected). Expiry is re-checked on every hit, so an
-- entry is never honoured past the token's own 'exp'; the effective revocation
-- window therefore equals the token lifetime.
--
-- Under 'lua-load' this table lives in the single shared Lua state and is
-- coherent across threads (Lua runs under HAProxy's global lock). Under
-- 'lua-load-per-thread' each thread keeps its own cache -- still correct, just
-- a lower hit rate.
local verifiedCache = {}
local verifiedCacheSize = 0
local VERIFIED_CACHE_MAX = 8192

local function verifiedCacheRemove(key)
  if verifiedCache[key] ~= nil then
    verifiedCache[key] = nil
    verifiedCacheSize = verifiedCacheSize - 1
  end
end

local function verifiedCachePurgeExpired(now)
  for k, v in pairs(verifiedCache) do
    if v.exp <= now then
      verifiedCacheRemove(k)
    end
  end
end

local function verifiedCachePut(key, payload, exp)
  if verifiedCache[key] == nil then
    if verifiedCacheSize >= VERIFIED_CACHE_MAX then
      -- Bounded: drop expired entries first; if still full, clear the table.
      -- Worst case we re-verify a few tokens -- correctness is unaffected.
      verifiedCachePurgeExpired(core.now().sec)
      if verifiedCacheSize >= VERIFIED_CACHE_MAX then
        -- Loud on purpose: a working set of live tokens above the cap means
        -- periodic full re-verification (CPU sawtooth), not a correctness bug.
        warn("jwtverify: verified-token cache flushed at " .. verifiedCacheSize
          .. " live entries; working set exceeds VERIFIED_CACHE_MAX")
        verifiedCache = {}
        verifiedCacheSize = 0
      end
    end
    verifiedCacheSize = verifiedCacheSize + 1
  end
  verifiedCache[key] = { payload = payload, exp = exp }
end

local function jwtverify(txn)
  local issuer = config.issuer
  local audience = config.audience
  local hmacSecret = config.hmacSecret

  local authHeader = txn.sf:req_hdr("Authorization")

  -- Fast path: a token we have already fully verified and that has not yet
  -- expired. Skips JSON decode and signature verification entirely.
  if authHeader ~= nil then
    local cached = verifiedCache[authHeader]
    if cached ~= nil then
      if cached.exp > core.now().sec then
        setVariablesFromPayload(txn, cached.payload)
        log("req.authorized = true (cached)")
        txn.set_var(txn, "txn.oauth_cache", "hit")
        txn.set_var(txn, "txn.authorized", true)
        return
      end
      -- Expired: drop it and fall through to full verification.
      verifiedCacheRemove(authHeader)
    end
  end

  -- 1. Decode and parse the JWT
  local token = decodeJwt(authHeader)

  if token == nil then
    log("Token could not be decoded.")
    goto out
  end

  -- Set an HAProxy variable for each field in the token payload
  setVariablesFromPayload(txn, token.payloaddecoded)

  -- 2. Verify the signature algorithm is supported (HS256, HS512, RS256)
  if algorithmIsValid(token) == false then
      log("Algorithm not valid.")
      goto out
  end

  -- 3. Verify the signature with the certificate
  if token.headerdecoded.alg == 'RS256' then
    if rs256SignatureIsValid(token, config.parsedKeys) == false then
      warn("Signature not valid for any provided public key.")
      goto out
    end
  elseif token.headerdecoded.alg == 'HS256' then
    if hs256SignatureIsValid(token, hmacSecret) == false then
      warn("Signature not valid.")
      goto out
    end
  elseif token.headerdecoded.alg == 'HS512' then
    if hs512SignatureIsValid(token, hmacSecret) == false then
      warn("Signature not valid.")
      goto out
    end
  end

  -- 4. Verify that the token is not expired
  if expirationIsValid(token) == false then
    warn("Token is expired.")
    goto out
  end

  -- 5. Verify the issuer
  if issuer ~= nil and issuerIsValid(token, issuer) == false then
    warn("Issuer not valid.")
    goto out
  end

  -- 6. Verify the audience
  if audience ~= nil and audienceIsValid(token, audience) == false then
    warn("Audience not valid.")
    goto out
  end

  -- Cache this verified token until its own expiry so subsequent presentations
  -- of the same token skip decode and signature verification.
  if authHeader ~= nil and type(token.payloaddecoded.exp) == "number" then
    verifiedCachePut(authHeader, token.payloaddecoded, token.payloaddecoded.exp)
  end

  -- 8. Set authorized variable
  log("req.authorized = true")
  -- 'miss' = authorized via full verification (and now cached). Exposed so the
  -- access-log format can record cache effectiveness in production; requests
  -- denied before this point leave the variable unset.
  txn.set_var(txn, "txn.oauth_cache", "miss")
  txn.set_var(txn, "txn.authorized", true)

  -- exit
  do return end

  -- way out. Display a message when running in debug mode
::out::
 log("req.authorized = false")
 txn.set_var(txn, "txn.authorized", false)
end

-- Called after the configuration is parsed.
-- Loads the OAuth public key for validating the JWT signature.
core.register_init(function()
  config.issuer = os.getenv("OAUTH_ISSUER")
  config.audience = os.getenv("OAUTH_AUDIENCE")
  config.keyPaths = os.getenv("OAUTH_KEY_PATHS")

  -- Debug defaults off (see fallback config). Set OAUTH_DEBUG=true (or 1/yes)
  -- to re-enable verbose per-request logging.
  local debugEnv = os.getenv("OAUTH_DEBUG")
  if debugEnv ~= nil then
    debugEnv = debugEnv:lower()
    config.debug = (debugEnv == "true" or debugEnv == "1" or debugEnv == "yes")
  end
  
  -- Load all public keys from the provided paths
  if config.keyPaths ~= nil then
    local paths = core.tokenize(config.keyPaths, " ")
    for _, path in ipairs(paths) do
      local pem = readAll(path)
      table.insert(config.publicKeys, pem)
      log("Loaded public key from: " .. path)
    end
  end

  -- Pre-parse the PEMs into key objects once, so signature verification does
  -- not rebuild them on every request (they are immutable for the process
  -- lifetime). A key that fails to parse here could never have verified a
  -- signature anyway, so alert loudly; if none parse, abort startup rather
  -- than run a proxy that rejects every RS256 token.
  config.parsedKeys = {}
  for i, pem in ipairs(config.publicKeys) do
    local ok, vkey = pcall(openssl.pkey.new, pem)
    if ok and vkey ~= nil then
      table.insert(config.parsedKeys, vkey)
    else
      core.Alert("jwtverify: failed to parse public key " .. i .. " of "
        .. #config.publicKeys .. ": " .. tostring(vkey))
    end
  end
  if #config.publicKeys > 0 and #config.parsedKeys == 0 then
    error("jwtverify: none of the " .. #config.publicKeys
      .. " configured public keys could be parsed; aborting startup")
  end
  
  -- when using an HS256 or HS512 signature
  config.hmacSecret = os.getenv("OAUTH_HMAC_SECRET")
  
  log("Issuer: " .. (config.issuer or "<none>"))
  log("Audience: " .. (config.audience or "<none>"))
  log("KeyPaths: " .. (config.keyPaths or "<none>"))
  log("Number of public keys loaded: " .. #config.publicKeys)
end)

-- Called on a request.
core.register_action('jwtverify', {'http-req'}, jwtverify, 0)