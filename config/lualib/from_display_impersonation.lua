-- MSG-1866: detect a brand name in the MIME From display name when the
-- structured From address belongs to an unrelated domain.

local brand_data = require "phish_url_heuristics"

local exports = {}
local SYMBOL = "FROM_DISPLAY_IMPERSONATION"
local brands = brand_data.brands
local brand_to_domains = brand_data.brand_to_domains

local function normalize_domain(domain)
  domain = string.lower(tostring(domain or ""))
  domain = domain:gsub("^%s+", ""):gsub("%s+$", "")
  return (domain:gsub("%.+$", ""))
end

local function address_domain(address)
  if not address then
    return nil
  end

  local domain = normalize_domain(address.domain)
  if domain ~= "" then
    return domain
  end

  local addr = tostring(address.addr or "")
  domain = normalize_domain(addr:match("@([^@<>%s,;]+)%s*>?%s*$"))
  return domain ~= "" and domain or nil
end

local function display_tokens(display_name)
  local tokens = {}
  for token in string.lower(tostring(display_name or "")):gmatch("[%a%d]+") do
    tokens[#tokens + 1] = token
  end
  return tokens
end

-- Match complete display-name tokens, including contiguous multi-token forms
-- such as "Bank of America" and "Office 365". This avoids treating a brand as
-- a substring of an unrelated word (for example, apple in pineapple).
local function display_brand(display_name)
  local tokens = display_tokens(display_name)

  for _, brand in ipairs(brands) do
    for first = 1, #tokens do
      local candidate = ""
      for last = first, #tokens do
        candidate = candidate .. tokens[last]
        if candidate == brand then
          return brand
        end
        if #candidate >= #brand then
          break
        end
      end
    end
  end

  return nil
end

local function domain_matches(from_domain, legitimate_domain)
  return from_domain == legitimate_domain or
    from_domain:sub(-#legitimate_domain - 1) == "." .. legitimate_domain
end

local function legitimate_brand_domain(brand, from_domain)
  for legitimate_domain in pairs(brand_to_domains[brand] or {}) do
    if domain_matches(from_domain, legitimate_domain) then
      return true
    end
  end
  return false
end

local function from_display_impersonation(task)
  for _, from in ipairs(task:get_from("mime") or {}) do
    local brand = display_brand(from.name)
    local from_domain = address_domain(from)
    if brand and from_domain and not legitimate_brand_domain(brand, from_domain) then
      return true, 1.0, {
        "brand=" .. brand,
        "from_domain=" .. from_domain,
      }
    end
  end

  return false
end

exports.brands = brands
exports.brand_to_domains = brand_to_domains
exports.callback = from_display_impersonation

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "prefilter",
  callback = from_display_impersonation,
  score = 4.0,
  group = "headers",
  description = "Brand display name is used from an unrelated sender domain",
})

return exports
