local module_dir = os.getenv("HOMOGLYPH_DETECTION_LUA_PATH") or "config/lualib"
package.path = module_dir .. "/?.lua;" .. package.path

local registered_symbol
local dependencies = {}
_G.rspamd_config = {
  register_symbol = function(_, definition)
    registered_symbol = definition
    return definition.name
  end,
  register_dependency = function(_, symbol, dependency)
    dependencies[symbol] = dependencies[symbol] or {}
    dependencies[symbol][dependency] = true
  end,
}

require "homoglyph_detection"

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local multi_tld_suffixes = {
  "co.uk", "co.jp", "co.kr", "co.nz", "co.in", "co.za",
  "com.au", "com.br", "com.mx", "com.cn", "com.hk", "com.tw",
  "com.sg", "com.my", "com.ph",
}

local function registered_domain(host)
  host = string.lower(host or ""):gsub("%.$", "")
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
  local host = value:match("^https?://([^/%?#]+)")
  assert(host, "test URL must include an http(s) scheme: " .. value)

  return setmetatable({
    get_host = function()
      return host
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

-- Represents the host value after Rspamd URL parsing. This is also used for
-- mapping characters that RFC-compliant parsers reject in literal DNS names.
local function url_host(host)
  return {
    get_host = function()
      return host
    end,
    get_tld = function()
      return registered_domain(host)
    end,
  }
end

local function task_with(options)
  options = options or {}
  local from_domain = options.from_domain
  local reply_domain = options.reply_domain

  return {
    get_text_parts = function()
      return {}
    end,
    get_urls = function()
      if options.url_host then
        return { url_host(options.url_host) }
      end
      if not options.url then
        return {}
      end
      return { url(options.url) }
    end,
    get_from = function(_, mode)
      eq(mode, "mime", "From address mode")
      if not from_domain then
        return nil
      end
      return { { addr = "sender@" .. from_domain, domain = from_domain } }
    end,
    get_reply_sender = function()
      if not reply_domain then
        return nil
      end
      return "reply@" .. reply_domain
    end,
  }
end

local function scan(options)
  local matched, multiplier, symbol_options = registered_symbol.callback(task_with(options))
  return matched or false, multiplier, symbol_options
end

local function assert_url_flagged(value, label)
  local matched, multiplier, options = scan({ url = value })
  eq(matched, true, label)
  eq(multiplier, 1.0, label .. " multiplier")
  eq(options[1], "homoglyph", label .. " reason")
end

local function assert_url_clean(value, label)
  local matched = scan({ url = value })
  eq(matched, false, label)
end

assert(registered_symbol, "LOOKALIKE_DOMAIN must be registered")
eq(registered_symbol.name, "LOOKALIKE_DOMAIN", "registered symbol name")
eq(registered_symbol.type, "prefilter", "registered symbol type")
eq(registered_symbol.score, 6.0, "registered symbol score")
eq(next(dependencies), nil, "registered dependencies")

assert_url_flagged("https://micros0ft-share.com/login", "0 maps to o in microsoft")
assert_url_flagged("https://paypa1-verify.com/login", "1 maps to l in paypal")
assert_url_flagged("https://g00gle-search.com/", "multiple 0 characters map to o")
assert_url_flagged("https://fac3book-login.com/", "3 maps to e")
assert_url_flagged("https://amaz0n-deal.com/", "0 maps to o in amazon")
assert_url_clean("https://microsoft.com/", "exact microsoft brand has no substitution")
assert_url_flagged("https://micros0ft.com/", "microsoft lookalike registered domain")
assert_url_clean("https://example.com/", "non-brand domain")
assert_url_flagged("https://rnicrosoft.com/", "rn maps to m")
assert_url_clean("https://paypal.com/", "exact paypal brand has no substitution")
assert_url_flagged("https://paypa1.com/", "paypal lookalike registered domain")

-- Cover the remaining required ASCII confusable mappings directly, including
-- characters that a strict URL parser may reject in a real DNS hostname.
local mapping_cases = {
  { "micro5oft.com", "microsoft", "5 maps to s" },
  { "vvellsfargo.com", "wellsfargo", "vv maps to w" },
  { "p@ypal.com", "paypal", "@ maps to a" },
  { "in$tagram.com", "instagram", "$ maps to s" },
  { "e8ay.com", "ebay", "8 maps to b" },
  { "7witter.com", "twitter", "7 maps to t" },
  { "1nstagram.com", "instagram", "1 maps to i" },
}
for _, case in ipairs(mapping_cases) do
  local mapping_matched, _, mapping_options = scan({ url_host = case[1] })
  eq(mapping_matched, true, case[3] .. " through URL callback")
  eq(mapping_options[4], "label=" .. case[1]:match("^[^.]+"), case[3] .. " URL label")
  eq(mapping_options[5], "brand=" .. case[2], case[3] .. " URL brand")

  mapping_matched, _, mapping_options = scan({ from_domain = case[1] })
  eq(mapping_matched, true, case[3] .. " through From callback")
  eq(mapping_options[2], "source=from", case[3] .. " From source")
  eq(mapping_options[5], "brand=" .. case[2], case[3] .. " From brand")
end

-- From domains are checked even when a message has no URLs.
local matched, _, options = scan({ from_domain = "micros0ft.com" })
eq(matched, true, "From lookalike domain")
eq(options[1], "homoglyph", "From lookalike reason")

-- A near-match Reply-To domain is suspicious even without a brand name.
matched, _, options = scan({ from_domain = "company.com", reply_domain = "cornpany.com" })
eq(matched, true, "From/Reply-To edit distance two")
eq(options[1], "reply_to_distance", "From/Reply-To reason")
eq(options[2], "distance=2", "From/Reply-To distance two option")

matched, _, options = scan({ from_domain = "company.com", reply_domain = "compamy.com" })
eq(matched, true, "From/Reply-To edit distance one")
eq(options[2], "distance=1", "From/Reply-To distance one option")

-- Equal, TLD-only, and substantially different From/Reply-To domains are clean.
matched = scan({ from_domain = "company.com", reply_domain = "company.com" })
eq(matched, false, "equal From/Reply-To domains")
matched = scan({ from_domain = "company.com", reply_domain = "unrelated.net" })
eq(matched, false, "unrelated From/Reply-To domains")
matched = scan({ from_domain = "company.com", reply_domain = "company.co" })
eq(matched, false, "TLD-only From/Reply-To difference")

-- R1 fix: Levenshtein distance against brand list (not just hard-coded substitutions)
-- paypall.com is edit distance 1 from "paypal" — should be caught
matched, _, options = scan({ url_host = "paypall.com" })
eq(matched, true, "paypall.com Levenshtein distance 1 from paypal")
eq(options[1], "levenshtein", "paypall.com detection reason")

-- payypall.com is edit distance 2 from "paypal" — should be caught
matched, _, options = scan({ url_host = "payypall.com" })
eq(matched, true, "payypall.com Levenshtein distance 2 from paypal")
eq(options[1], "levenshtein", "payypall.com detection reason")

-- From domain with Levenshtein match
matched, _, options = scan({ from_domain = "paypall.com" })
eq(matched, true, "From paypall.com Levenshtein distance 1")

-- R1 fix: Sibling subdomains must NOT trigger false positives
-- mail1.company.com vs mail2.company.com should NOT fire (same registered domain)
matched = scan({ from_domain = "mail1.company.com", reply_domain = "mail2.company.com" })
eq(matched, false, "sibling subdomains mail1 vs mail2 should not trigger")

-- R2 fix: Official brand subdomains must NOT trigger Levenshtein false positives
-- apps.apple.com — "apps" is distance 2 from "apple" but it's a legitimate subdomain
matched = scan({ url_host = "apps.apple.com" })
eq(matched, false, "apps.apple.com should not trigger (legitimate Apple subdomain)")

-- app.example.com — "app" is distance 3 from "apple", should not trigger
matched = scan({ url_host = "app.example.com" })
eq(matched, false, "app.example.com should not trigger (short non-brand subdomain)")

-- From app.example.com should not trigger
matched = scan({ from_domain = "app.example.com" })
eq(matched, false, "From app.example.com should not trigger")

-- Legitimate brand domain (exact match) should NOT fire via Levenshtein (distance 0)
matched = scan({ from_domain = "paypal.com" })
eq(matched, false, "exact brand domain paypal.com should not trigger")

-- Non-brand domain should NOT fire
matched = scan({ from_domain = "example.com" })
eq(matched, false, "non-brand example.com should not trigger")

print("homoglyph_detection_test: PASS")
