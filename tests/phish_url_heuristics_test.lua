local module_dir = os.getenv("PHISH_URL_HEURISTICS_LUA_PATH") or "config/lualib"
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

-- Multi-label TLD suffixes where the registered domain is 3 labels deep
local multi_tld_suffixes = {
  "co.uk", "co.jp", "co.kr", "co.nz", "co.in", "co.za",
  "com.au", "com.br", "com.mx", "com.cn", "com.hk", "com.tw",
  "com.sg", "com.my", "com.ph",
}

local function registered_domain(host)
  -- Check for multi-label TLD
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
assert_flagged("https://a.b.c.d.account.xyz/login", "excessive_subdomains")
assert_flagged("https://evil.com/paypal/login", "brand_in_path")
assert_clean("https://paypal.com/")
assert_clean("https://mail.google.com/")
assert_clean("https://google.com/search?q=paypal")

-- R1/R2 regressions
assert_clean("https://www.amazon.co.uk/")
assert_clean("https://apple.com.cn/")
assert_clean("https://notpaypal.com/")
assert_clean("https://example.com/pineapple-cake")
assert_flagged("https://login.paypal.top/paypal/login", "brand_in_path")
assert_flagged("https://evil.com/paypal.html", "brand_in_path")

-- R3 regressions
assert_clean("https://sellercentral.amazon.co.uk/")
assert_clean("https://ebay.com.sg/")
assert_clean("https://ebay.com.my/")
assert_clean("https://www.dropbox.com/")
-- Alias domain negatives: citi.com is legitimate for citibank, x.com for twitter
assert_clean("https://citi.com/citibank")
assert_clean("https://x.com/twitter")
-- Cross-brand: dropbox.com should NOT suppress paypal in path
assert_flagged("https://www.dropbox.com/scl/fi/attacker/paypal", "brand_in_path")
-- Rspamd normalizes + to space: "account+paypal" becomes "account paypal"
-- Test with the normalized form (what Rspamd actually presents to the callback)
assert_flagged("https://evil.com/account paypal", "brand_in_path")

print("phish_url_heuristics_test: PASS")
