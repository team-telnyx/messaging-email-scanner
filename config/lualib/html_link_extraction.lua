-- MSG-1833: extract HTML anchor destinations before URL rules run and detect
-- visible-domain/href-domain mismatches independently of the rendered body.

local rspamd_url = require "rspamd_url"

local exports = {}
local SYMBOL = "HTML_LINK_MISMATCH"

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
  host = string.lower(host or "")
  return (host:gsub("^%.*", ""):gsub("%.+$", ""))
end

local function split_labels(host)
  local labels = {}
  for label in normalize_host(host):gmatch("[^.]+") do
    labels[#labels + 1] = label
  end
  return labels
end

local function fallback_registered_domain(host)
  local labels = split_labels(host)
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
  local domain = normalize_host(url and url:get_tld() or nil)
  if domain ~= "" then
    return domain
  end

  return fallback_registered_domain(url and url:get_host() or nil)
end

local function decode_basic_entities(value)
  return (value
    :gsub("&[Nn][Bb][Ss][Pp];", " ")
    :gsub("&#160;", " ")
    :gsub("&#x[Aa]0;", " ")
    :gsub("&[Aa][Mm][Pp];", "&")
    :gsub("&[Ll][Tt];", "<")
    :gsub("&[Gg][Tt];", ">")
    :gsub("&[Qq][Uu][Oo][Tt];", '"')
    :gsub("&#39;", "'")
  )
end

local function normalize_display_text(value)
  value = decode_basic_entities(tostring(value or ""))
  value = value:gsub("<[^>]->", " ")
  value = value:gsub("%s+", " ")
  return value:match("^%s*(.-)%s*$") or ""
end

local function valid_domain_candidate(candidate)
  if not candidate or #candidate > 253 or not candidate:find("%.") then
    return false
  end

  for label in candidate:gmatch("[^.]+") do
    if #label == 0 or #label > 63 or label:match("^%-") or label:match("%-$") then
      return false
    end
  end

  local tld = candidate:match("([^.]+)$")
  return tld ~= nil and #tld >= 2 and tld:match("^[%a%d%-]+$") ~= nil
end

function exports.extract_display_domain(display_text)
  local text = string.lower(normalize_display_text(display_text))

  -- Match the ticket's domain-like display text while trimming URL punctuation.
  -- Requiring the candidate to start/end with an alphanumeric avoids accepting
  -- sentence punctuation as part of the hostname.
  for candidate in text:gmatch("[%w][%w%.%-]*%.[%w%-]+") do
    local normalized_candidate = candidate:gsub("%.+$", "")
    if valid_domain_candidate(normalized_candidate) then
      return normalized_candidate
    end
  end

  return nil
end

local function parse_href(task, href)
  href = decode_basic_entities(tostring(href or "")):match("^%s*(.-)%s*$") or ""
  if href == "" then
    return nil
  end

  -- Protocol-relative links have a real network destination; normalize them so
  -- rspamd_url can expose host/TLD and all downstream URL rules can inspect them.
  if href:match("^//") then
    href = "https:" .. href
  end

  if not href:lower():match("^https?://") then
    return nil
  end

  return rspamd_url.create(task:get_mempool(), href)
end

local function display_registered_domain(task, display_domain)
  local display_url = rspamd_url.create(task:get_mempool(), "https://" .. display_domain)
  if display_url then
    return registered_domain(display_url)
  end

  return fallback_registered_domain(display_domain)
end

local function check_anchor(task, tag, seen_urls)
  local href = tag:get_attribute("href")
  local url = parse_href(task, href)
  if not url then
    return nil
  end

  local url_text = tostring(url)
  if not seen_urls[url_text] then
    task:inject_url(url)
    seen_urls[url_text] = true
  end

  local display_domain = exports.extract_display_domain(tag:get_content())
  if not display_domain then
    return nil
  end

  local href_domain = registered_domain(url)
  local visible_domain = display_registered_domain(task, display_domain)
  if href_domain ~= "" and visible_domain ~= "" and href_domain ~= visible_domain then
    return {
      "display=" .. visible_domain,
      "href=" .. href_domain,
    }
  end

  return nil
end

local function html_link_extraction(task)
  local mismatches = {}
  local seen_urls = {}

  for _, part in ipairs(task:get_text_parts() or {}) do
    if part:is_html() then
      local html = part:get_html()
      if html then
        html:foreach_tag("a", function(tag)
          local mismatch = check_anchor(task, tag, seen_urls)
          if mismatch then
            mismatches[#mismatches + 1] = mismatch
          end
          return false
        end)
      end
    end
  end

  if #mismatches > 0 then
    -- The symbol is one-shot per message, but retain evidence for every mismatch.
    local options = {}
    for _, mismatch in ipairs(mismatches) do
      options[#options + 1] = mismatch[1]
      options[#options + 1] = mismatch[2]
    end
    return true, 1.0, options
  end

  return false
end

exports.callback = html_link_extraction

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "normal",
  callback = html_link_extraction,
  score = 6.0,
  group = "url",
  description = "HTML anchor display domain differs from destination domain",
})

-- Ensure the existing URL checks see destinations injected by this prefilter,
-- even when the rendered anchor text is generic (for example, "Click here").
rspamd_config:register_dependency("PHISH_URL_HEURISTIC", SYMBOL)
rspamd_config:register_dependency("PHISHED_URL_BLOCKLIST", SYMBOL)

return exports
