-- MSG-1830: local phishing URL heuristics that do not require blocklists.

local exports = {}

local SYMBOL = "PHISH_URL_HEURISTIC"

local brands = {
  "paypal",
  "apple",
  "google",
  "microsoft",
  "amazon",
  "netflix",
  "facebook",
  "instagram",
  "linkedin",
  "twitter",
  "bankofamerica",
  "chase",
  "wellsfargo",
  "citibank",
  "americanexpress",
  "dropbox",
  "adobe",
  "ebay",
}

local brand_set = {}
for _, brand in ipairs(brands) do
  brand_set[brand] = true
end

-- Known legitimate brand domains (including country TLDs).
-- Subdomain impersonation check must accept any of these as valid registered domains.
local brand_domains = {
  "paypal.com",
  "apple.com",
  "google.com",
  "microsoft.com",
  "amazon.com",
  "amazon.co.uk",
  "amazon.de",
  "amazon.fr",
  "amazon.it",
  "amazon.es",
  "amazon.ca",
  "amazon.com.mx",
  "amazon.com.br",
  "amazon.co.jp",
  "amazon.in",
  "amazon.com.au",
  "netflix.com",
  "facebook.com",
  "instagram.com",
  "linkedin.com",
  "twitter.com",
  "x.com",
  "bankofamerica.com",
  "chase.com",
  "wellsfargo.com",
  "citibank.com",
  "citi.com",
  "americanexpress.com",
  "dropbox.com",
  "adobe.com",
  "ebay.com",
  "ebay.co.uk",
  "ebay.de",
  "ebay.fr",
  "ebay.it",
  "ebay.es",
  "ebay.ca",
  "ebay.com.au",
  "ebay.at",
  "ebay.be",
  "ebay.ch",
  "ebay.ie",
  "ebay.nl",
  "ebay.pl",
  "ebay.com.sg",
  "ebay.com.my",
  "ebay.ph",
  "ebay.com.hk",
  "ebay.com.tw",
  "apple.com.cn",
  "apple.co.jp",
  "apple.co.uk",
  "google.co.uk",
  "google.co.jp",
  "google.de",
  "google.fr",
  "microsoft.co.uk",
}

local brand_domain_set = {}
for _, d in ipairs(brand_domains) do
  brand_domain_set[d] = true
end

exports.brands = brands
exports.brand_set = brand_set
exports.brand_domain_set = brand_domain_set

local function normalize_host(host)
  host = string.lower(host or "")
  return (host:gsub("^%.*", ""):gsub("%.+$", ""))
end

local function host_labels(host)
  local labels = {}
  for label in host:gmatch("[^.]+") do
    labels[#labels + 1] = label
  end
  return labels
end

-- Check if any label of the host exactly matches a brand name.
-- This prevents "notpaypal.com" from matching brand "paypal".
local function host_has_brand_label(host)
  for label in host:gmatch("[^.]+") do
    if brand_set[label] then
      return label
    end
  end
  return nil
end

local function fallback_registered_domain(labels)
  if #labels < 2 then
    return labels[1] or ""
  end
  -- Check last 3 labels for country TLDs like co.uk, co.jp
  if #labels >= 3 then
    local last3 = labels[#labels - 2] .. "." .. labels[#labels - 1] .. "." .. labels[#labels]
    -- Common second-level TLDs where the real domain is 3 labels deep
    local sld = labels[#labels - 1] .. "." .. labels[#labels]
    if sld == "co.uk" or sld == "co.jp" or sld == "co.kr" or sld == "co.nz" or
       sld == "co.in" or sld == "co.za" or sld == "com.au" or sld == "com.br" or
       sld == "com.mx" or sld == "com.cn" or sld == "com.hk" or sld == "com.tw" then
      return last3
    end
  end
  return labels[#labels - 1] .. "." .. labels[#labels]
end

local function registered_domain(url, labels)
  local domain = url:get_tld()
  domain = normalize_host(domain)
  if domain == "" then
    return fallback_registered_domain(labels)
  end
  return domain
end

-- Word-boundary check: brand must appear as a complete path segment,
-- not as a substring of another word (e.g. "pineapple" should not match "apple").
-- Rspamd normalizes + to space in URLs, so include space in the delimiter set.
local function path_has_brand_segment(path, brand)
  path = string.lower(path or "")
  if path == "" then
    return false
  end
  -- Tokenize on all non-alphanumeric boundaries (covers /, ?, &, =, -, _, ., +, space, etc.)
  for segment in path:gmatch("[%a%d]+") do
    if segment == brand then
      return true
    end
  end
  return false
end

-- Map brand name to its legitimate domain set for cross-brand suppression.
local brand_to_domains = {}
for _, brand in ipairs(brands) do
  brand_to_domains[brand] = {}
end
for _, domain in ipairs(brand_domains) do
  -- Extract brand from domain (first label before the TLD)
  local brand_label = string.match(domain, "^([%a]+)%.")
  if brand_label and brand_to_domains[brand_label] then
    brand_to_domains[brand_label][domain] = true
  end
end

local function brand_in_path(host, path, url, labels)
  path = string.lower(path or "")
  if path == "" then
    return nil
  end

  local domain = registered_domain(url, labels)

  for _, brand in ipairs(brands) do
    if path_has_brand_segment(path, brand) then
      -- Only suppress if THIS specific brand's domain set contains the registered domain.
      -- This prevents dropbox.com from suppressing paypal detection in the path.
      if brand_to_domains[brand] and brand_to_domains[brand][domain] then
        -- The brand in the path IS the owner of this domain — legitimate, skip
      else
        return brand
      end
    end
  end

  return nil
end

function exports.check_url(url)
  local host = normalize_host(url:get_host())
  if host == "" then
    return nil
  end

  local labels = host_labels(host)
  local first_label = labels[1]

  -- Subdomain impersonation: first label is a brand but the registered domain
  -- is NOT a known legitimate brand domain.
  if brand_set[first_label] then
    local domain = registered_domain(url, labels)
    if not brand_domain_set[domain] then
      return "subdomain_impersonation", host
    end
  end

  -- Excessive subdomains: count labels BEYOND the registered domain.
  -- e.g. sellercentral.amazon.co.uk > registered domain = amazon.co.uk (3 labels)
  -- > 1 subdomain label (sellercentral) > NOT excessive.
  -- com.security.verify.account.xyz > registered domain = account.xyz (2 labels)
  -- > 2 subdomain labels > NOT excessive (but caught by subdomain impersonation if brand).
  -- Only flag 4+ subdomain labels beyond the registered domain.
  local reg_domain = registered_domain(url, labels)
  local reg_labels = host_labels(reg_domain)
  local subdomain_count = #labels - #reg_labels
  if subdomain_count >= 4 then
    return "excessive_subdomains", host
  end

  local path_brand = brand_in_path(host, url:get_path(), url, labels)
  if path_brand then
    return "brand_in_path", host, path_brand
  end

  return nil
end

local function phish_url_heuristic(task)
  for _, url in ipairs(task:get_urls() or {}) do
    local reason, host, brand = exports.check_url(url)
    if reason then
      local options = { reason, host }
      if brand then
        options[#options + 1] = "brand=" .. brand
      end
      return true, 1.0, options
    end
  end

  return false
end

exports.callback = phish_url_heuristic

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "prefilter",
  callback = phish_url_heuristic,
  score = 5.0,
  group = "url",
  description = "URL matches local phishing impersonation heuristics",
})

return exports
