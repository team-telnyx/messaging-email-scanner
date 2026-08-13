-- MSG-1830: local phishing URL heuristics that do not require blocklists.

local html_link_extraction = require "html_link_extraction"

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
  "docusign",
  "dropbox",
  "adobe",
  "zoom",
  "ebay",
  "office365",
  "docusign",
  "zoom",
  "slack",
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
  "office.com",
  "office365.com",
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
  "docusign.com",
  "dropbox.com",
  "adobe.com",
  "zoom.us",
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
  "docusign.com",
  "zoom.us",
  "slack.com",
}

local brand_domain_set = {}
for _, d in ipairs(brand_domains) do
  brand_domain_set[d] = true
end

-- These exact domains are reserved for documentation. Treating a brand-like
-- subdomain as attacker controlled would make the RFC-safe fixture URL
-- office365.example.org look malicious on its own.
local reserved_example_domains = {
  ["example.com"] = true,
  ["example.net"] = true,
  ["example.org"] = true,
}

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

-- Check if any complete label or hyphen-delimited label component matches a
-- brand. This catches office365-login.evil.test without matching notpaypal.com.
local function host_has_brand_label(host)
  for label in host:gmatch("[^.]+") do
    if brand_set[label] then
      return label
    end
    for component in label:gmatch("[^%-_]+") do
      if brand_set[component] then
        return component
      end
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
-- Defined explicitly (not inferred from first label) to handle alias domains
-- like citi.com (brand=citibank) and x.com (brand=twitter).
local brand_to_domains = {
  paypal = { ["paypal.com"] = true },
  apple = { ["apple.com"] = true, ["apple.com.cn"] = true, ["apple.co.jp"] = true, ["apple.co.uk"] = true },
  google = { ["google.com"] = true, ["google.co.uk"] = true, ["google.co.jp"] = true, ["google.de"] = true, ["google.fr"] = true },
  microsoft = { ["microsoft.com"] = true, ["microsoft.co.uk"] = true, ["office.com"] = true, ["office365.com"] = true },
  amazon = { ["amazon.com"] = true, ["amazon.co.uk"] = true, ["amazon.de"] = true, ["amazon.fr"] = true, ["amazon.it"] = true, ["amazon.es"] = true, ["amazon.ca"] = true, ["amazon.com.mx"] = true, ["amazon.com.br"] = true, ["amazon.co.jp"] = true, ["amazon.in"] = true, ["amazon.com.au"] = true },
  netflix = { ["netflix.com"] = true },
  facebook = { ["facebook.com"] = true },
  instagram = { ["instagram.com"] = true },
  linkedin = { ["linkedin.com"] = true },
  twitter = { ["twitter.com"] = true, ["x.com"] = true },
  bankofamerica = { ["bankofamerica.com"] = true },
  chase = { ["chase.com"] = true },
  wellsfargo = { ["wellsfargo.com"] = true },
  citibank = { ["citibank.com"] = true, ["citi.com"] = true },
  americanexpress = { ["americanexpress.com"] = true },
  docusign = { ["docusign.com"] = true },
  dropbox = { ["dropbox.com"] = true },
  adobe = { ["adobe.com"] = true },
  zoom = { ["zoom.us"] = true },
  ebay = { ["ebay.com"] = true, ["ebay.co.uk"] = true, ["ebay.de"] = true, ["ebay.fr"] = true, ["ebay.it"] = true, ["ebay.es"] = true, ["ebay.ca"] = true, ["ebay.com.au"] = true, ["ebay.at"] = true, ["ebay.be"] = true, ["ebay.ch"] = true, ["ebay.ie"] = true, ["ebay.nl"] = true, ["ebay.pl"] = true, ["ebay.com.sg"] = true, ["ebay.com.my"] = true, ["ebay.ph"] = true, ["ebay.com.hk"] = true, ["ebay.com.tw"] = true },
  office365 = { ["office.com"] = true, ["office365.com"] = true, ["microsoft.com"] = true },
  docusign = { ["docusign.com"] = true },
  zoom = { ["zoom.us"] = true, ["zoom.com"] = true },
  slack = { ["slack.com"] = true },
}

-- Shared by header-based brand impersonation checks. Export the canonical map
-- so detectors do not maintain divergent copies of legitimate brand domains.
exports.brand_to_domains = brand_to_domains

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

  -- Subdomain impersonation: any subdomain label is a brand but the registered
  -- domain is not one of that brand's legitimate domains.
  local subdomain_brand = host_has_brand_label(host)
  if subdomain_brand then
    local domain = registered_domain(url, labels)
    local legitimate_domains = brand_to_domains[subdomain_brand] or {}
    if not legitimate_domains[domain] and not reserved_example_domains[domain] then
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
  local urls = {}
  local seen = {}

  local function add_url(url)
    if not url then
      return
    end

    local key = tostring(url)
    if not seen[key] then
      seen[key] = true
      urls[#urls + 1] = url
    end
  end

  for _, url in ipairs(task:get_urls() or {}) do
    add_url(url)
  end

  -- Do not rely on task:get_urls() to preserve every multipart/alternative
  -- representation. Explicitly parse hrefs from every HTML text part.
  for _, url in ipairs(html_link_extraction.extract_html_urls(task)) do
    add_url(url)
  end

  for _, url in ipairs(urls) do
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
