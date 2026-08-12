local module_dir = assert(
  os.getenv("PHISH_URL_HEURISTICS_LUA_PATH"),
  "PHISH_URL_HEURISTICS_LUA_PATH is required"
)
package.path = module_dir .. "/?.lua;" .. package.path

local registered_symbol
_G.rspamd_config = {
  register_symbol = function(_, definition)
    registered_symbol = definition
    return 1
  end,
}

local heuristics = require "phish_url_heuristics"

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function registered_domain(host)
  return host:match("([^.]+%.[^.]+)$") or host
end

local function url(value)
  local host, remainder = value:match("^https?://([^/]+)(.*)$")
  assert(host, "test URL must include an http(s) scheme: " .. value)

  local path = remainder:match("^([^?]*)") or ""
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

local function scan(value)
  local task = {
    get_urls = function()
      return { url(value) }
    end,
  }

  local matched, multiplier, options = registered_symbol.callback(task)
  if not matched then
    return {}
  end
  return {
    {
      symbol = registered_symbol.name,
      multiplier = multiplier,
      options = options,
    },
  }
end

local function assert_flagged(value, expected_reason)
  local results = scan(value)
  eq(#results, 1, value .. " result count")
  eq(results[1].symbol, "PHISH_URL_HEURISTIC", value .. " symbol")
  eq(results[1].multiplier, 1.0, value .. " multiplier")
  eq(results[1].options[1], expected_reason, value .. " reason")
end

local function assert_clean(value)
  eq(#scan(value), 0, value .. " should not be flagged")
end

assert(registered_symbol, "PHISH_URL_HEURISTIC must be registered")
eq(registered_symbol.name, "PHISH_URL_HEURISTIC", "registered symbol name")
eq(registered_symbol.type, "prefilter", "registered symbol type")
eq(registered_symbol.score, 5.0, "registered symbol score")

local expected_brands = {
  "paypal", "apple", "google", "microsoft", "amazon", "netflix",
  "facebook", "instagram", "linkedin", "twitter", "bankofamerica",
  "chase", "wellsfargo", "citibank", "americanexpress", "dropbox",
  "adobe", "ebay",
}
for _, brand in ipairs(expected_brands) do
  eq(heuristics.brand_set[brand], true, "brand list contains " .. brand)
end

assert_flagged("https://paypal.com.evil.com/login", "subdomain_impersonation")
assert_flagged("https://com.security.verify.account.xyz/login", "excessive_subdomains")
assert_flagged("https://evil.com/paypal/login", "brand_in_path")
assert_clean("https://paypal.com/")
assert_clean("https://mail.google.com/")
assert_clean("https://google.com/search?q=paypal")

print("phish_url_heuristics_test: PASS")
