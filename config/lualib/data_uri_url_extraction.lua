-- MSG-1870: expose HTTP(S) URLs embedded in textual data URIs to Rspamd's
-- phishing and lookalike-domain rules.

local rspamd_url = require "rspamd_url"
local rspamd_util = require "rspamd_util"
-- rspamd_logger is available in live Rspamd but not in unit tests
local rspamd_logger = package.loaded["rspamd_logger"]

local exports = {}
local SYMBOL = "DATA_URI_URL_EXTRACTION"
local MAX_DECODED_BYTES = 10 * 1024
local MAX_DATA_URIS = 100
local MAX_ENCODED_BYTES = math.ceil(MAX_DECODED_BYTES * 4 / 3) + 4

local supported_media_types = {
  ["text/html"] = true,
  ["text/plain"] = true,
}

local html_url_attributes = {
  a = { "href" },
  area = { "href" },
  base = { "href" },
  button = { "formaction" },
  form = { "action" },
  frame = { "src" },
  iframe = { "src" },
  input = { "formaction", "src" },
  link = { "href" },
  object = { "data" },
}

local function trim(value)
  return tostring(value or ""):match("^%s*(.-)%s*$") or ""
end

local function url_text(url)
  if url.get_raw then
    local ok, raw = pcall(url.get_raw, url)
    if ok and raw ~= nil and tostring(raw) ~= "" then
      return tostring(raw)
    end
  end
  if url.get_text then
    local ok, text = pcall(url.get_text, url)
    if ok and text ~= nil and tostring(text) ~= "" then
      return tostring(text)
    end
  end
  return tostring(url or "")
end

local function is_data_url(url)
  if url.get_protocol then
    local ok, protocol = pcall(url.get_protocol, url)
    if ok and string.lower(tostring(protocol or "")) == "data" then
      return true
    end
  end
  return url_text(url):lower():match("^data:") ~= nil
end

local function percent_decode_limited(value, limit)
  local output = {}
  local output_bytes = 0
  local index = 1
  value = tostring(value or "")

  while index <= #value do
    local character
    local hex = value:sub(index + 1, index + 2)
    if value:sub(index, index) == "%" and #hex == 2 and hex:match("^%x%x$") then
      character = string.char(tonumber(hex, 16))
      index = index + 3
    else
      character = value:sub(index, index)
      index = index + 1
    end

    output_bytes = output_bytes + #character
    if output_bytes > limit then
      return nil
    end
    output[#output + 1] = character
  end

  return table.concat(output)
end

local function parse_metadata(metadata)
  local segments = {}
  for segment in (tostring(metadata or "") .. ";"):gmatch("(.-);") do
    segments[#segments + 1] = trim(segment)
  end

  local media_type = string.lower(segments[1] or "")
  if media_type == "" then
    media_type = "text/plain"
  end
  if not supported_media_types[media_type] then
    return nil
  end

  local base64 = false
  for index = 2, #segments do
    if string.lower(segments[index]) == "base64" then
      base64 = true
    end
  end
  return media_type, base64
end

local function decoded_data_uri(value)
  value = tostring(value or "")
  if not value:lower():match("^data:") then
    return nil
  end

  local comma = value:find(",", 6, true)
  if not comma then
    return nil
  end

  local media_type, base64 = parse_metadata(value:sub(6, comma - 1))
  if not media_type then
    return nil
  end

  local payload = value:sub(comma + 1)
  if not base64 then
    return percent_decode_limited(payload, MAX_DECODED_BYTES)
  end

  -- Percent escapes are part of the data URI layer and must be removed before
  -- base64 decoding. A valid base64 payload is bounded to avoid decoding content
  -- that cannot fit under the 10 KiB decoded-content limit.
  local encoded = percent_decode_limited(payload, MAX_ENCODED_BYTES * 3)
  if not encoded then
    return nil
  end
  encoded = encoded:gsub("%s", "")
  if #encoded > MAX_ENCODED_BYTES then
    return nil
  end

  local ok, decoded = pcall(rspamd_util.decode_base64, encoded)
  if not ok or decoded == nil then
    return nil
  end
  decoded = tostring(decoded)
  if #decoded > MAX_DECODED_BYTES then
    return nil
  end
  return decoded
end

function exports.extract_urls(content)
  local urls = {}
  local seen = {}

  -- Stop at whitespace, markup, or string delimiters. Then remove punctuation
  -- commonly terminating a URL in JavaScript or prose.
  for candidate in tostring(content or ""):gmatch("[%a][%w+%.%-]*://[^%s<>\"'`]+") do
    local scheme = string.lower(tostring(candidate:match("^([^:]+)") or ""))
    if scheme == "http" or scheme == "https" then
      local value = candidate:gsub("[%]%)}>,;]+$", "")
      if value ~= "" and not seen[value] then
        seen[value] = true
        urls[#urls + 1] = value
      end
    end
  end

  return urls
end

function exports.decode(value)
  return decoded_data_uri(value)
end

local function collect_data_uris(task)
  local values = {}
  local seen = {}

  local function add(value)
    value = tostring(value or "")
    if value:lower():match("^data:") and not seen[value] and #values < MAX_DATA_URIS then
      seen[value] = true
      values[#values + 1] = value
    end
  end

  -- Some Rspamd versions may retain non-network URL schemes in the task set.
  for _, url in ipairs(task:get_urls() or {}) do
    if is_data_url(url) then
      add(url_text(url))
    end
  end

  -- Rspamd 3.10 intentionally excludes data: attributes from task:get_urls().
  -- Read URL-bearing HTML attributes directly so form actions and hrefs are not
  -- lost before this symbol can inspect them.
  if task.get_text_parts then
    for _, part in ipairs(task:get_text_parts() or {}) do
      if part.is_html and part:is_html() and part.get_html then
        local html = part:get_html()
        if html and html.foreach_tag then
          for tag_name, attributes in pairs(html_url_attributes) do
            html:foreach_tag(tag_name, function(tag)
              for _, attribute in ipairs(attributes) do
                add(tag:get_attribute(attribute))
              end
              return #values >= MAX_DATA_URIS
            end)
          end
        end
      end
      if #values >= MAX_DATA_URIS then
        break
      end
    end
  end

  return values
end

local function data_uri_url_extraction(task)
  local extracted = 0
  local seen = {}



  for _, url in ipairs(task:get_urls() or {}) do
    seen[tostring(url)] = true
  end

  for _, data_uri in ipairs(collect_data_uris(task)) do
    local content = decoded_data_uri(data_uri)
    if content then
      for _, value in ipairs(exports.extract_urls(content)) do
        if not seen[value] then
          local parsed = rspamd_url.create(task:get_mempool(), value)
          if parsed then
            local normalized = tostring(parsed)
            if normalized ~= "" and not seen[normalized] then
              seen[value] = true
              seen[normalized] = true
              task:inject_url(parsed)
              extracted = extracted + 1
            end
          end
        end
      end
    end
  end

  if extracted > 0 then
    return true, 1.0, { "count=" .. extracted }
  end
  return false
end

exports.callback = data_uri_url_extraction

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "prefilter",
  callback = data_uri_url_extraction,
  score = 0.0,
  group = "url",
  description = "HTTP(S) URL extracted from a textual data URI",
})

-- URL heuristics must run after embedded URLs have been injected.
rspamd_config:register_dependency("PHISH_URL_HEURISTIC", SYMBOL)
rspamd_config:register_dependency("LOOKALIKE_DOMAIN", SYMBOL)

return exports
