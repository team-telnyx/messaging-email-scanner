
-- Mock rspamd_logger
package.preload['rspamd_logger'] = {
  warnx = function(...) end,
  errx = function(...) end,
  infox = function(...) end,
  msgx = function(...) end,
}

-- Mock rspamd_url  
_G.rspamd_url = {
  create = function(s) return { _url = s, _host = s:match('://([^/]+)') or '', _query = s:match('%?(.*)') or '', _path = s:match('://[^/]+(/[^?]*)') or '/' } end,
}

-- Mock rspamd_logger before requiring the module
package.preload["rspamd_logger"] = function()
  return {
    warnx = function(...) end,
    errx = function(...) end,
    infox = function(...) end,
    msgx = function(...) end,
  }
end

local module_dir = os.getenv("OPEN_REDIRECT_DETECTION_LUA_PATH") or "config/lualib"
package.path = module_dir .. "/?.lua;" .. package.path

local registered_symbols = {}
_G.rspamd_config = {
  register_symbol = function(_, definition)
    registered_symbols[definition.name] = definition
    return definition.name
  end,
}

local multi_tld_suffixes = {
  "co.uk", "co.jp", "co.kr", "co.nz", "co.in", "co.za",
  "com.au", "com.br", "com.mx", "com.cn", "com.hk", "com.tw",
  "com.sg", "com.my", "com.ph",
}

local function registered_domain(host)
  host = string.lower(host or ""):gsub(":%d+$", ""):gsub("%.$", "")
  for _, suffix in ipairs(multi_tld_suffixes) do
    if host:sub(-#suffix) == suffix then
      local before = host:sub(1, #host - #suffix - 1)
      local label = before:match("([^.]+)$")
      if label then
        return label .. "." .. suffix
      end
    end
  end
  return host:match("([^.]+%.[^.]+)$") or host
end

local function parsed_url(value)
  local host, remainder = value:match("^https?://([^/%?#]+)(.*)$")
  if not host then
    return nil
  end
  local path = remainder:match("^([^?#]*)") or ""

  return setmetatable({
    get_host = function()
      return host
    end,
    get_path = function()
      return path
    end,
    get_tld = function()
      return registered_domain(host)
    end,
  }, {
    __tostring = function()
      return value
    end,
  })
end

package.preload["rspamd_url"] = function()
  return {
    create = function(_, value)
      return parsed_url(value)
    end,
  }
end

require "open_redirect_detection"

local open_redirect = registered_symbols.OPEN_REDIRECT

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function contains(results, symbol)
  for _, result in ipairs(results) do
    if result.symbol == symbol then
      return true
    end
  end
  return false
end

local function scan(value)
  local inserted = {}
  local task = {
    get_urls = function()
      return { assert(parsed_url(value), "invalid outer test URL: " .. value) }
    end,
    get_mempool = function()
      return {}
    end,
    insert_result = function(_, symbol, multiplier, options)
      inserted[#inserted + 1] = {
        symbol = symbol,
        multiplier = multiplier,
        options = options,
      }
    end,
  }

  local matched, multiplier, options = open_redirect.callback(task)
  if matched then
    inserted[#inserted + 1] = {
      symbol = open_redirect.name,
      multiplier = multiplier,
      options = options,
    }
  end
  return inserted
end

local function assert_open_redirect(value, label)
  local results = scan(value)
  eq(contains(results, "OPEN_REDIRECT"), true, label)
  return results
end

local function assert_clean(value, label)
  local results = scan(value)
  eq(contains(results, "OPEN_REDIRECT"), false, label)
  eq(#results, 0, label .. " inserted symbol count")
end

assert(open_redirect, "OPEN_REDIRECT must be registered")
eq(open_redirect.name, "OPEN_REDIRECT", "registered symbol name")
eq(open_redirect.type, "normal", "registered symbol type")
eq(open_redirect.score, 6.0, "registered symbol score")

-- Required acceptance cases.
assert_open_redirect(
  "https://legitimate.example/redirect?redirect=https://phishing.example/login",
  "external phishing.example redirect"
)
assert_clean(
  "https://same-domain.com/redirect?url=https://same-domain.com/path",
  "same registered domain redirect"
)
assert_clean(
  "https://legitimate.example/continue?next=/relative/path",
  "relative redirect target"
)
local results = assert_open_redirect(
  "https://legitimate.example/slink?redirect=https://paypa1.example/login",
  "lookalike redirect target"
)
eq(contains(results, "LOOKALIKE_DOMAIN"), true, "lookalike target inserts LOOKALIKE_DOMAIN")
assert_clean(
  "https://legitimate.example/news?id=123",
  "URL without redirect parameter"
)
assert_open_redirect(
  "https://legitimate.example/go?dest=https://evil.example/collect",
  "external evil.example destination"
)
assert_open_redirect(
  "https://legitimate.example/redirect?redirect=ws://phishing.example/socket",
  "external WebSocket redirect target"
)
assert_open_redirect(
  "https://legitimate.example/redirect?redirect=wss://phishing.example/session",
  "external secure WebSocket redirect target"
)

-- The motivating red-team URL: a legitimate LinkedIn URL redirects to a
-- brand-modifier lookalike domain.
results = assert_open_redirect(
  "https://www.linkedin.com/slink?code=abc123&redirect=https://linkedin-secure.com/profile-view?id=8x4k",
  "LinkedIn slink to linkedin-secure.com"
)
eq(contains(results, "LOOKALIKE_DOMAIN"), true, "brand-modifier target inserts LOOKALIKE_DOMAIN")

-- Generic B2B terms have no canonical brand domain. They remain eligible for
-- homoglyph checks but must not become brand-modifier evidence on their own.
results = assert_open_redirect(
  "https://legitimate.example/go?url=https://supplier-portal.com",
  "redirect to generic supplier portal"
)
eq(contains(results, "LOOKALIKE_DOMAIN"), false, "generic B2B target has no lookalike evidence")

-- Brand-in-subdomain targets reuse PHISH_URL_HEURISTIC evidence.
results = assert_open_redirect(
  "https://legitimate.example/url?url=https://paypal.evil.example/login",
  "brand in target subdomain"
)
eq(contains(results, "PHISH_URL_HEURISTIC"), true, "brand subdomain inserts PHISH_URL_HEURISTIC")

-- Every required redirect parameter name is recognized case-insensitively.
for _, parameter in ipairs({
  "redirect", "url", "next", "goto", "return", "dest", "destination",
  "redir", "continue", "to",
}) do
  assert_open_redirect(
    "https://legitimate.example/page?" .. string.upper(parameter) .. "=https%3A%2F%2Fpaypa1.example%2Flogin",
    "redirect parameter " .. parameter
  )
end

-- Redirect paths inspect external URL values even under provider-specific keys.
for _, path in ipairs({ "slink", "redirect", "url", "go", "jump", "continue" }) do
  assert_open_redirect(
    "https://legitimate.example/" .. path .. "?target=https://paypa1.example/login",
    "redirect path /" .. path .. "?"
  )
end

-- A URL-valued unknown parameter is not enough without a redirect path.
assert_clean(
  "https://legitimate.example/search?target=https://paypa1.example/login",
  "unknown parameter on a non-redirect path"
)

print("open_redirect_detection_test: PASS")
