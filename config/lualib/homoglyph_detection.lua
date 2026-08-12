-- MSG-1847: detect ASCII homoglyph/lookalike domains in URLs and sender headers.

local exports = {}

local SYMBOL = "LOOKALIKE_DOMAIN"

-- Keep this list in sync with phish_url_heuristics.lua.
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

local confusables = {
  { source = "rn", replacements = { "m" } },
  { source = "vv", replacements = { "w" } },
  { source = "0", replacements = { "o" } },
  { source = "1", replacements = { "l", "i" } },
  { source = "3", replacements = { "e" } },
  { source = "5", replacements = { "s" } },
  { source = "@", replacements = { "a" } },
  { source = "$", replacements = { "s" } },
  { source = "8", replacements = { "b" } },
  { source = "7", replacements = { "t" } },
}

local common_multi_label_suffixes = {
  ["co.uk"] = true,
  ["co.jp"] = true,
  ["co.kr"] = true,
  ["co.nz"] = true,
  ["co.in"] = true,
  ["co.za"] = true,
  ["com.au"] = true,
  ["com.br"] = true,
  ["com.mx"] = true,
  ["com.cn"] = true,
  ["com.hk"] = true,
  ["com.tw"] = true,
  ["com.sg"] = true,
  ["com.my"] = true,
  ["com.ph"] = true,
}

local function normalize_host(host)
  host = string.lower(tostring(host or ""))
  host = host:gsub("^%s+", ""):gsub("%s+$", "")
  host = host:gsub("^%.*", ""):gsub("%.+$", "")
  return (host:gsub(":%d+$", ""))
end

local function split_labels(host)
  local labels = {}
  for label in normalize_host(host):gmatch("[^.]+") do
    labels[#labels + 1] = label
  end
  return labels
end

local function suffix_matches(host_labels, registered_labels)
  if #registered_labels == 0 or #registered_labels > #host_labels then
    return false
  end

  local offset = #host_labels - #registered_labels
  for index, label in ipairs(registered_labels) do
    if host_labels[offset + index] ~= label then
      return false
    end
  end
  return true
end

-- Return the SLD and all subdomain labels while excluding the public suffix.
local function domain_labels(host, registered_domain)
  local host_labels = split_labels(host)
  if #host_labels == 0 then
    return {}
  end

  local registered_labels = split_labels(registered_domain)
  if suffix_matches(host_labels, registered_labels) then
    local result = {}
    local subdomain_count = #host_labels - #registered_labels
    for index = 1, subdomain_count do
      result[#result + 1] = host_labels[index]
    end
    -- Rspamd's get_tld() returns the registered domain. Its first label is the SLD.
    result[#result + 1] = registered_labels[1]
    return result
  end

  local suffix_count = 1
  if #host_labels >= 2 then
    local suffix = host_labels[#host_labels - 1] .. "." .. host_labels[#host_labels]
    if common_multi_label_suffixes[suffix] then
      suffix_count = 2
    end
  end

  local result = {}
  local last_domain_label = math.max(1, #host_labels - suffix_count)
  for index = 1, last_domain_label do
    result[#result + 1] = host_labels[index]
  end
  return result
end

-- Compare a domain-label component to a brand without materializing an
-- exponential number of variants. The recursion explores the unchanged input
-- and each valid confusable replacement, and only succeeds if at least one
-- replacement was required.
local function component_matches_brand(component, brand)
  local memo = {}

  local function matches(source_index, brand_index, changed)
    local key = source_index .. ":" .. brand_index .. ":" .. tostring(changed)
    if memo[key] ~= nil then
      return memo[key]
    end

    if source_index > #component or brand_index > #brand then
      local result = source_index > #component and brand_index > #brand and changed
      memo[key] = result
      return result
    end

    if component:sub(source_index, source_index) == brand:sub(brand_index, brand_index) and
       matches(source_index + 1, brand_index + 1, changed) then
      memo[key] = true
      return true
    end

    for _, mapping in ipairs(confusables) do
      local source_end = source_index + #mapping.source - 1
      if component:sub(source_index, source_end) == mapping.source then
        for _, replacement in ipairs(mapping.replacements) do
          local replacement_end = brand_index + #replacement - 1
          if brand:sub(brand_index, replacement_end) == replacement and
             matches(source_end + 1, replacement_end + 1, true) then
            memo[key] = true
            return true
          end
        end
      end
    end

    memo[key] = false
    return false
  end

  return matches(1, 1, false)
end

local function label_components(label)
  local components = { label }
  if label:find("[-_]") then
    for component in label:gmatch("[^-_]+") do
      components[#components + 1] = component
    end
  end
  return components
end

function exports.check_domain(host, registered_domain)
  host = normalize_host(host)
  if host == "" then
    return nil
  end

  for _, label in ipairs(domain_labels(host, registered_domain)) do
    for _, component in ipairs(label_components(label)) do
      for _, brand in ipairs(brands) do
        if component_matches_brand(component, brand) then
          return brand, component
        end
      end
    end
  end

  return nil
end

local function address_domain(address)
  if address == nil then
    return nil
  end

  if type(address) == "table" and address.domain then
    local domain = normalize_host(address.domain)
    return domain ~= "" and domain or nil
  end

  if type(address) == "table" and address.addr then
    address = address.addr
  end

  local value = string.lower(tostring(address))
  local domain = value:match("@([^@<>%s,;]+)%s*>?%s*$")
  domain = normalize_host(domain)
  return domain ~= "" and domain or nil
end

local function header_domain(task, header_name)
  if not task.get_header then
    return nil
  end
  return address_domain(task:get_header(header_name))
end

local function from_domain(task)
  if task.get_from then
    local from_addresses = task:get_from("mime")
    if from_addresses and from_addresses[1] then
      local domain = address_domain(from_addresses[1])
      if domain then
        return domain
      end
    end
  end
  return header_domain(task, "From")
end

local function reply_to_domain(task)
  if task.get_reply_sender then
    local domain = address_domain(task:get_reply_sender())
    if domain then
      return domain
    end
  end
  return header_domain(task, "Reply-To")
end

local function levenshtein(left, right)
  local previous = {}
  for column = 0, #right do
    previous[column] = column
  end

  for row = 1, #left do
    local current = { [0] = row }
    local left_char = left:sub(row, row)
    for column = 1, #right do
      local cost = left_char == right:sub(column, column) and 0 or 1
      current[column] = math.min(
        current[column - 1] + 1,
        previous[column] + 1,
        previous[column - 1] + cost
      )
    end
    previous = current
  end

  return previous[#right]
end

local function public_suffix(domain)
  local labels = split_labels(domain)
  if #labels < 2 then
    return labels[#labels] or ""
  end

  local suffix = labels[#labels - 1] .. "." .. labels[#labels]
  if common_multi_label_suffixes[suffix] then
    return suffix
  end
  return labels[#labels]
end

-- Extract the registered domain from a hostname (e.g. mail1.company.com → company.com)
local function registered_domain_from_host(host)
  local labels = split_labels(host)
  if #labels < 2 then
    return host
  end
  local suffix = labels[#labels - 1] .. "." .. labels[#labels]
  if #labels >= 3 and common_multi_label_suffixes[suffix] then
    return labels[#labels - 2] .. "." .. suffix
  end
  return suffix
end

exports.levenshtein = levenshtein
exports.brands = brands

local function lookalike_domain(task)
  for _, url in ipairs(task:get_urls() or {}) do
    local host = normalize_host(url:get_host())
    local registered_domain = url:get_tld()
    local brand, component = exports.check_domain(host, registered_domain)
    if brand then
      return true, 1.0, {
        "homoglyph",
        "source=url",
        "host=" .. host,
        "label=" .. component,
        "brand=" .. brand,
      }
    end
    -- Also check Levenshtein distance against brand list for non-homoglyph lookalikes
    -- (e.g. paypall.com → distance 1 from "paypal")
    for _, label in ipairs(domain_labels(host, registered_domain)) do
      for _, component in ipairs(label_components(label)) do
        for _, brand in ipairs(brands) do
          local distance = levenshtein(component, brand)
          if distance >= 1 and distance <= 2 then
            return true, 1.0, {
              "levenshtein",
              "source=url",
              "host=" .. host,
              "label=" .. component,
              "brand=" .. brand,
              "distance=" .. distance,
            }
          end
        end
      end
    end
  end

  local mime_from_domain = from_domain(task)
  if mime_from_domain then
    local brand, component = exports.check_domain(mime_from_domain)
    if brand then
      return true, 1.0, {
        "homoglyph",
        "source=from",
        "host=" .. mime_from_domain,
        "label=" .. component,
        "brand=" .. brand,
      }
    end
    -- Levenshtein check for From domain against brand list
    local from_labels = domain_labels(mime_from_domain, nil)
    for _, label in ipairs(from_labels) do
      for _, component in ipairs(label_components(label)) do
        for _, brand in ipairs(brands) do
          local distance = levenshtein(component, brand)
          if distance >= 1 and distance <= 2 then
            return true, 1.0, {
              "levenshtein",
              "source=from",
              "host=" .. mime_from_domain,
              "label=" .. component,
              "brand=" .. brand,
              "distance=" .. distance,
            }
          end
        end
      end
    end
  end

  local mime_reply_to_domain = reply_to_domain(task)
  if mime_from_domain and mime_reply_to_domain and mime_from_domain ~= mime_reply_to_domain then
    -- Compare registered domains (not full hostnames) to avoid false positives
    -- on legitimate sibling subdomains like mail1.company.com vs mail2.company.com
    local from_reg = registered_domain_from_host(mime_from_domain)
    local reply_reg = registered_domain_from_host(mime_reply_to_domain)
    if from_reg and reply_reg and from_reg ~= reply_reg then
      if public_suffix(mime_from_domain) == public_suffix(mime_reply_to_domain) then
        local distance = levenshtein(from_reg, reply_reg)
        if distance >= 1 and distance <= 2 then
          return true, 1.0, {
            "reply_to_distance",
            "distance=" .. distance,
            "from=" .. from_reg,
            "reply_to=" .. reply_reg,
          }
        end
      end
    end
  end

  return false
end

exports.callback = lookalike_domain

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "prefilter",
  callback = lookalike_domain,
  score = 6.0,
  group = "url",
  description = "URL or sender domain is an ASCII homoglyph/lookalike",
})

return exports
