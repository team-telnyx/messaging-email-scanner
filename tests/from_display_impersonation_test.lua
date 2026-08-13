local module_dir = os.getenv("FROM_DISPLAY_IMPERSONATION_LUA_PATH") or "config/lualib"
package.path = module_dir .. "/?.lua;" .. package.path

local registered_symbols = {}
_G.rspamd_config = {
  register_symbol = function(_, definition)
    registered_symbols[definition.name] = definition
    return definition.name
  end,
}

-- phish_url_heuristics loads html_link_extraction, whose production adapter
-- requires rspamd_url at module load time. The display-name detector never
-- creates URLs, so a minimal adapter is sufficient for this unit test.
package.preload["rspamd_url"] = function()
  return {
    create = function()
      return nil
    end,
  }
end

local detector = require "from_display_impersonation"
local brand_data = require "phish_url_heuristics"
local symbol = registered_symbols.FROM_DISPLAY_IMPERSONATION

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function task_with(display_name, domain, addr)
  return {
    get_from = function(_, mode)
      eq(mode, "mime", "From address mode")
      return {
        {
          name = display_name,
          domain = domain,
          addr = addr or (domain and "sender@" .. domain or nil),
        },
      }
    end,
  }
end

local function scan(display_name, domain, addr)
  local matched, multiplier, options = symbol.callback(task_with(display_name, domain, addr))
  return matched or false, multiplier, options
end

local function assert_flagged(display_name, domain, expected_brand, label, addr)
  local matched, multiplier, options = scan(display_name, domain, addr)
  eq(matched, true, label)
  eq(multiplier, 1.0, label .. " multiplier")
  eq(options[1], "brand=" .. expected_brand, label .. " brand option")
  eq(options[2], "from_domain=" .. string.lower(domain or addr:match("@([^@]+)$")), label .. " domain option")
end

local function assert_clean(display_name, domain, label, addr)
  local matched = scan(display_name, domain, addr)
  eq(matched, false, label)
end

assert(symbol, "FROM_DISPLAY_IMPERSONATION must be registered")
eq(symbol.name, "FROM_DISPLAY_IMPERSONATION", "registered symbol name")
eq(symbol.type, "prefilter", "registered symbol type")
eq(symbol.score, 4.0, "registered symbol score")
eq(symbol.group, "headers", "registered symbol group")

-- The detector must reuse the canonical brand names and domains rather than
-- carrying another copy that can drift.
eq(detector.brands, brand_data.brands, "shared brand list")
eq(detector.brand_to_domains, brand_data.brand_to_domains, "shared brand-domain map")

assert_flagged("PayPal", "accounts-verify.net", "paypal", "PayPal on unrelated domain")
assert_flagged("PAYPAL Security", "accounts-verify.net", "paypal", "brand matching is case insensitive")
assert_flagged("Bank of America Alerts", "secure-notices.net", "bankofamerica", "spaced brand name")
assert_flagged("Office 365 Support", "account-alerts.net", "office365", "alphanumeric spaced brand name")

assert_clean("PayPal", "paypal.com", "PayPal root domain is legitimate")
assert_clean("PayPal Security", "notices.paypal.com", "PayPal subdomain is legitimate")
assert_clean("Microsoft Account Team", "office.com", "Microsoft alias domain is legitimate")
assert_clean("Office 365 Support", "login.microsoft.com", "Office 365 Microsoft alias is legitimate")
assert_clean("PayPal", "PAYPAL.COM.", "legitimate domain normalization")

-- Domain suffix checks must be boundary safe.
assert_flagged("PayPal", "paypal.com.evil.net", "paypal", "brand domain embedded in attacker domain")

-- Generic role names and words that merely contain a short brand are not
-- specific brand display names.
assert_clean("admin", "accounts-verify.net", "generic admin display name")
assert_clean("support", "accounts-verify.net", "generic support display name")
assert_clean("Pineapple Market", "fruit.example", "brand substring inside another word")
assert_clean(nil, "accounts-verify.net", "missing display name")

-- Rspamd normally supplies .domain; retain a structured-address fallback for
-- adapters that provide only .addr.
assert_flagged("PayPal", nil, "paypal", "address domain fallback", "sender@accounts-verify.net")

-- Every structured MIME From mailbox must be inspected. An attacker can place a
-- benign mailbox first and the impersonating mailbox second.
local multi_matched, multi_multiplier, multi_options = symbol.callback({
  get_from = function(_, mode)
    eq(mode, "mime", "multi-address From mode")
    return {
      { name = "Alice", domain = "example.com", addr = "alice@example.com" },
      { name = "PayPal", domain = "accounts-verify.net", addr = "alert@accounts-verify.net" },
    }
  end,
})
eq(multi_matched, true, "second From address is inspected")
eq(multi_multiplier, 1.0, "second From address multiplier")
eq(multi_options[1], "brand=paypal", "second From address brand option")
eq(multi_options[2], "from_domain=accounts-verify.net", "second From address domain option")

print("from_display_impersonation_test: PASS")
