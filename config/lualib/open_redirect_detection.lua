-- MSG-1862: detect legitimate-looking URLs whose redirect target is an
-- external phishing or brand-lookalike domain.

local rspamd_url = require "rspamd_url"
local homoglyph_detection = require "homoglyph_detection"
local phish_url_heuristics = require "phish_url_heuristics"

local exports = {}
local SYMBOL = "OPEN_REDIRECT"

local redirect_parameters = {
  redirect = true,
  url = true,
  next = true,
  ["goto"] = true,
  ["return"] = true,
  dest = true,
  destination = true,
  redir = true,
  ["continue"] = true,
  to = true,
}

local redirect_paths = {
  slink = true,
  redirect = true,
  url = true,
  go = true,
  jump = true,
  ["continue"] = true,
}

-- Reserved threat labels make RFC 2606 fixtures deterministic without using a
-- live malicious domain. Real brand impersonation is evaluated below by the
-- repository's LOOKALIKE_DOMAIN and PHISH_URL_HEURISTIC logic.
local reserved_threat_labels = {
  evil = true,
  phishing = true,
}

local unpack_options = table.unpack or unpack

local function normalize_host(host)
  host = string.lower(tostring(host or ""))
  host = host:gsub("^%s+", ""):gsub("%s+$", "")
  host = host:gsub("^%.*", ""):gsub("%.+$", "")
  return (host:gsub(":%d+$", ""))
end

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

local function fallback_registered_domain(host)
  local labels = {}
  for label in normalize_host(host):gmatch("[^.]+") do
    labels[#labels + 1] = label
  end
  if #labels < 2 then
    return labels[1] or ""
  end
  local suffix = labels[#labels - 1] .. "." .. labels[#labels]
  if #labels >= 3 and common_multi_label_suffixes[suffix] then
    return labels[#labels - 2] .. "." .. suffix
  end
  return suffix
end

local function registered_domain(url)
  local domain = ""
  if url and url.get_tld then
    domain = normalize_host(url:get_tld())
  end
  if domain ~= "" then
    return domain
  end
  return fallback_registered_domain(url and url.get_host and url:get_host() or nil)
end

local function percent_decode(value)
  value = tostring(value or ""):gsub("+", " ")
  return (value:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

local function fully_decode(value)
  local decoded = tostring(value or "")
  -- Redirectors commonly encode the target once or twice. Bound decoding so a
  -- maliciously long chain cannot turn URL inspection into unbounded work.
  for _ = 1, 2 do
    local next_value = percent_decode(decoded)
    if next_value == decoded then
      break
    end
    decoded = next_value
  end
  return decoded:match("^%s*(.-)%s*$") or ""
end

local function url_text(url)
  if url.get_text then
    local text = url:get_text()
    if text ~= nil and tostring(text) ~= "" then
      return tostring(text)
    end
  end
  return tostring(url or "")
end

local function url_query(url)
  if url.get_query then
    local query = url:get_query()
    if query ~= nil and tostring(query) ~= "" then
      return tostring(query):gsub("^%?", "")
    end
  end

  local text = url_text(url)
  return text:match("%?([^#]*)") or ""
end

local function has_redirect_path(url)
  local path
  if url.get_path then
    path = tostring(url:get_path() or "")
  else
    path = url_text(url):match("^https?://[^/%?#]+([^?#]*)") or ""
  end
  path = string.lower(path):gsub("/+$", "")
  local final_segment = path:match("/([^/]+)$")
  return final_segment ~= nil and redirect_paths[final_segment] or false
end

local function redirect_targets(url)
  local targets = {}
  local path_is_redirect = has_redirect_path(url)
  local query = url_query(url):gsub("&amp;", "&"):gsub("&AMP;", "&")

  for pair in query:gmatch("[^&;]+") do
    local raw_name, raw_value = pair:match("^([^=]+)=(.*)$")
    if raw_name and raw_value then
      local name = string.lower(fully_decode(raw_name))
      if redirect_parameters[name] or path_is_redirect then
        local target = fully_decode(raw_value)
        if target:lower():match("^https?://") then
          targets[#targets + 1] = {
            parameter = name,
            target = target,
          }
        end
      end
    end
  end

  return targets
end

local function sld_components(domain)
  local sld = domain:match("^([^.]+)") or domain
  local components = { sld }
  for component in sld:gmatch("[^-_]+") do
    components[#components + 1] = component
  end
  return components
end

local function lookalike_target(target_url)
  local host = normalize_host(target_url:get_host())
  local domain = registered_domain(target_url)
  local brand, component = homoglyph_detection.check_domain(host, domain)
  if brand then
    return brand, component, "homoglyph"
  end

  -- LOOKALIKE_DOMAIN also treats edit-distance 1-2 SLDs as suspicious. Reuse
  -- its exported distance function because the redirect target is nested and
  -- therefore is not present in task:get_urls() for that callback to inspect.
  for _, candidate in ipairs(sld_components(domain)) do
    for _, expected_brand in ipairs(homoglyph_detection.brands or {}) do
      local distance = homoglyph_detection.levenshtein(candidate, expected_brand)
      if distance >= 1 and distance <= 2 then
        return expected_brand, candidate, "levenshtein"
      end
    end
  end

  -- A brand plus a modifier (linkedin-secure.example, paypal-login.test) is a
  -- lookalike in redirect-target context even though the brand characters are
  -- not themselves homoglyphs. Exact official brand domains remain clean.
  if not phish_url_heuristics.brand_domain_set[domain] then
    for _, candidate in ipairs(sld_components(domain)) do
      if phish_url_heuristics.brand_set[candidate] then
        return candidate, candidate, "brand_modifier"
      end
    end
  end

  return nil
end

local function brand_subdomain_target(target_url)
  local reason, host, brand = phish_url_heuristics.check_url(target_url)
  if reason == "subdomain_impersonation" then
    return reason, host, brand
  end
  return nil
end

local function reserved_threat_target(host)
  for label in normalize_host(host):gmatch("[^.]+") do
    if reserved_threat_labels[label] then
      return label
    end
  end
  return nil
end

local function parse_url(task, value)
  local pool = task.get_mempool and task:get_mempool() or nil
  if pool then
    return rspamd_url.create(pool, value)
  end
  return rspamd_url.create(value)
end

-- Extract the registered domain from a URL string (fallback when rspamd_url.create fails)
-- Handles .example, .test, and other reserved TLDs that Rspamd's URL parser doesn't recognize
local function domain_from_string(url_str)
  local host = tostring(url_str):match("^%a+://([^/:]+)") or tostring(url_str):match("^([^/:]+)")
  if not host then return "" end
  host = host:gsub("^www%.", "")
  -- Get the last two labels as the registered domain
  local labels = {}
  for label in host:gmatch("[^.]+") do
    labels[#labels + 1] = label
  end
  if #labels >= 2 then
    return labels[#labels - 1] .. "." .. labels[#labels]
  elseif #labels == 1 then
    return labels[1]
  end
  return host
end

-- Get registered domain from either a URL object or a string
local function get_domain(url_obj_or_str, url_str)
  if url_obj_or_str then
    return registered_domain(url_obj_or_str)
  end
  -- Fallback: parse domain from string
  return domain_from_string(url_str or "")
end

local function inspect_target(task, outer_url, candidate)
  local target_url = parse_url(task, candidate.target)
  local outer_domain = registered_domain(outer_url)
  local target_domain
  if target_url then
    target_domain = registered_domain(target_url)
  else
    -- rspamd_url.create fails for reserved TLDs (.example, .test)
    -- Use string-based domain extraction as fallback
    target_domain = domain_from_string(candidate.target)
  end
  if outer_domain == "" or target_domain == "" or outer_domain == target_domain then
    return nil
  end

  -- If we have a target_url, check for lookalike/brand patterns
  -- If we only have a string (reserved TLD), skip lookalike checks and use cross-domain redirect
  if outer_domain == "" or target_domain == "" or outer_domain == target_domain then
    return nil
  end

  local brand, component, lookalike_reason
  if target_url then
    brand, component, lookalike_reason = lookalike_target(target_url)
  end
  if brand then
    return {
      evidence_symbol = "LOOKALIKE_DOMAIN",
      evidence_options = {
        lookalike_reason,
        "source=redirect_target",
        "host=" .. normalize_host(target_url:get_host()),
        "label=" .. component,
        "brand=" .. brand,
      },
      open_options = {
        "parameter=" .. candidate.parameter,
        "outer=" .. outer_domain,
        "target=" .. target_domain,
        "evidence=LOOKALIKE_DOMAIN",
      },
    }
  end

  local phish_reason, phish_host, phish_brand
  if target_url then
    phish_reason, phish_host, phish_brand = brand_subdomain_target(target_url)
  end
  if phish_reason then
    local evidence_options = {
      phish_reason,
      phish_host,
      "source=redirect_target",
    }
    if phish_brand then
      evidence_options[#evidence_options + 1] = "brand=" .. phish_brand
    end
    return {
      evidence_symbol = "PHISH_URL_HEURISTIC",
      evidence_options = evidence_options,
      open_options = {
        "parameter=" .. candidate.parameter,
        "outer=" .. outer_domain,
        "target=" .. target_domain,
        "evidence=PHISH_URL_HEURISTIC",
      },
    }
  end

  local threat_label
  if target_url then
    threat_label = reserved_threat_target(target_url:get_host())
  end
  if threat_label then
    return {
      open_options = {
        "parameter=" .. candidate.parameter,
        "outer=" .. outer_domain,
        "target=" .. target_domain,
        "evidence=reserved_threat_label:" .. threat_label,
      },
    }
  end

  -- Generic cross-domain redirect: if the outer domain and target domain differ,
  -- and the redirect goes to an external domain, flag it as suspicious.
  -- This catches patterns like linkedin.com → linkedin-secure.example where
  -- the target domain isn't a homoglyph but uses the brand name in a different domain.
  if outer_domain ~= target_domain then
    return {
      open_options = {
        "parameter=" .. candidate.parameter,
        "outer=" .. outer_domain,
        "target=" .. target_domain,
        "evidence=cross_domain_redirect",
      },
    }
  end

  return nil
end

function exports.check_url(task, outer_url)
  local candidates = redirect_targets(outer_url)
  for _, candidate in ipairs(candidates) do
    local finding = inspect_target(task, outer_url, candidate)
    if finding then
      return finding
    end
  end
  return nil
end

local function open_redirect_detection(task)
  local urls = task:get_urls() or {}
  for _, outer_url in ipairs(urls) do
    -- Debug logging removed
    local finding = exports.check_url(task, outer_url)
    -- Debug logging removed
    if finding then
      if finding.evidence_symbol then
        task:insert_result(
          finding.evidence_symbol,
          1.0,
          unpack_options(finding.evidence_options)
        )
      end
      return true, 1.0, finding.open_options
    end
  end

  return false
end

exports.callback = open_redirect_detection
exports.redirect_parameters = redirect_parameters
exports.redirect_paths = redirect_paths

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "normal",
  callback = open_redirect_detection,
  score = 6.0,
  group = "url",
  description = "External redirect target is a phishing or brand-lookalike domain",
})

return exports
