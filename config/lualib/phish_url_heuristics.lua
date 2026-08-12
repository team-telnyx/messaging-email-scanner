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

exports.brands = brands
exports.brand_set = brand_set

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

local function fallback_registered_domain(labels)
  if #labels < 2 then
    return labels[1] or ""
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

local function brand_in_path(host, path)
  path = string.lower(path or "")
  if path == "" then
    return nil
  end

  for _, brand in ipairs(brands) do
    if path:find(brand, 1, true) and not host:find(brand, 1, true) then
      return brand
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

  if brand_set[first_label] then
    local domain = registered_domain(url, labels)
    local expected_domain = first_label .. ".com"
    if domain ~= expected_domain then
      return "subdomain_impersonation", host
    end
  end

  if #labels >= 4 then
    return "excessive_subdomains", host
  end

  local path_brand = brand_in_path(host, url:get_path())
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
