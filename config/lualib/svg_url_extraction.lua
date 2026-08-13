-- MSG-1859: expose web URLs embedded in SVG MIME parts to Rspamd's
-- existing URL phishing and lookalike-domain rules.

local rspamd_url = require "rspamd_url"
local rspamd_util = require "rspamd_util"

local exports = {}
local SYMBOL = "SVG_URL_EXTRACTION"

local supported_attributes = {
  foreignobject = { "data" },
  image = { "href", "xlink:href" },
  use = { "href" },
  a = { "href" },
}

local function normalize_type(value)
  return string.lower(tostring(value or ""))
end

function exports.is_svg_type(main_type, subtype)
  return normalize_type(main_type) == "image" and normalize_type(subtype) == "svg+xml"
end

local function utf8_character(codepoint)
  if codepoint <= 0x7f then
    return string.char(codepoint)
  elseif codepoint <= 0x7ff then
    return string.char(
      0xc0 + math.floor(codepoint / 0x40),
      0x80 + (codepoint % 0x40)
    )
  elseif codepoint <= 0xffff then
    return string.char(
      0xe0 + math.floor(codepoint / 0x1000),
      0x80 + (math.floor(codepoint / 0x40) % 0x40),
      0x80 + (codepoint % 0x40)
    )
  elseif codepoint <= 0x10ffff then
    return string.char(
      0xf0 + math.floor(codepoint / 0x40000),
      0x80 + (math.floor(codepoint / 0x1000) % 0x40),
      0x80 + (math.floor(codepoint / 0x40) % 0x40),
      0x80 + (codepoint % 0x40)
    )
  end
  return ""
end

local function decode_xml_entities(value)
  value = tostring(value or "")
  value = value:gsub("&#[xX]([%da-fA-F]+);", function(hex)
    local codepoint = tonumber(hex, 16)
    if codepoint and codepoint <= 0x10ffff then
      return utf8_character(codepoint)
    end
    return ""
  end)
  value = value:gsub("&#(%d+);", function(decimal)
    local codepoint = tonumber(decimal, 10)
    if codepoint and codepoint <= 0x10ffff then
      return utf8_character(codepoint)
    end
    return ""
  end)
  return (value
    :gsub("&[Aa][Mm][Pp];", "&")
    :gsub("&[Qq][Uu][Oo][Tt];", '"')
    :gsub("&[Aa][Pp][Oo][Ss];", "'")
    :gsub("&[Ll][Tt];", "<")
    :gsub("&[Gg][Tt];", ">")
  )
end

local function trim(value)
  return tostring(value or ""):match("^%s*(.-)%s*$") or ""
end

local function is_network_url(value)
  value = trim(decode_xml_entities(value))
  if value:match("^//") then
    return "https:" .. value
  end
  local lower_value = value:lower()
  if lower_value:match("^https?://") or lower_value:match("^wss?://") then
    return value
  end
  return nil
end

local function create_web_url(mempool, value)
  local url = rspamd_url.create(mempool, value)
  if url then
    return url
  end

  -- Rspamd 3.10 cannot create URL objects for WebSocket schemes. Map them to
  -- their equivalent HTTP transports so existing host/path phishing rules can
  -- inspect the URL after it is injected into task:get_urls().
  local scheme, remainder = tostring(value):match("^([Ww][Ss][Ss]?)://(.*)$")
  if scheme then
    local compatible_scheme = scheme:lower() == "wss" and "https" or "http"
    return rspamd_url.create(mempool, compatible_scheme .. "://" .. remainder)
  end
  return nil
end

local function parse_attributes(raw_attributes)
  local attributes = {}
  for name, quote, value in tostring(raw_attributes or ""):gmatch(
    "([%a_][%w_.:%-]*)%s*=%s*([\"'])(.-)%2"
  ) do
    attributes[string.lower(name)] = value
  end
  return attributes
end

function exports.extract_urls(svg)
  local urls = {}
  local seen = {}
  local xml = tostring(svg or "")

  -- Comments and processing instructions are not part of the SVG element tree.
  -- Strip them before matching tags so commented-out payloads are not promoted.
  xml = xml:gsub("<!%-%-.-%-%->", "")
  xml = xml:gsub("<%?.-%?>", "")

  -- SVG is XML, so URL-bearing attributes are quoted in valid documents. Match
  -- only the supported element/attribute pairs instead of treating arbitrary
  -- XML attributes or text as navigable URLs.
  for qualified_name, raw_attributes in xml:gmatch(
    "<%s*([%a_][%w_.:%-]*)%s*([^>]*)>"
  ) do
    local element = string.lower(qualified_name):gsub("^.*:", "")
    local attribute_names = supported_attributes[element]
    if attribute_names then
      local attributes = parse_attributes(raw_attributes)
      for _, attribute_name in ipairs(attribute_names) do
        local value = is_network_url(attributes[attribute_name])
        if value and not seen[value] then
          seen[value] = true
          urls[#urls + 1] = value
        end
      end
    end
  end

  return urls
end

local function looks_like_svg(content)
  content = tostring(content or "")
  content = content:gsub("^\239\187\191", "")
  return content:lower():find("<%s*svg[%s>]", 1) ~= nil
end

local function svg_content(part)
  local content = part:get_content()
  if content == nil then
    return nil
  end

  content = tostring(content)

  -- Rspamd 3.10.2's mime_part:get_content() returns parsed_data, which is
  -- already transfer-decoded. The fallback handles unit adapters and any
  -- runtime that exposes the base64 body despite declaring base64 CTE, while
  -- the SVG sniff prevents corrupting already-decoded content.
  local cte = part.get_cte and normalize_type(part:get_cte()) or ""
  if cte == "base64" and not looks_like_svg(content) then
    local ok, decoded = pcall(rspamd_util.decode_base64, content)
    if ok and decoded ~= nil then
      content = tostring(decoded)
    end
  end

  return content
end

local function svg_url_extraction(task)
  local extracted = {}
  local seen = {}

  for _, part in ipairs(task:get_parts() or {}) do
    local main_type, subtype = part:get_type()
    if exports.is_svg_type(main_type, subtype) then
      local content = svg_content(part)
      for _, value in ipairs(exports.extract_urls(content)) do
        if not seen[value] then
          -- Do not mark the URL as `content`: task:get_urls() excludes content
          -- URLs by default, and the existing repository heuristics consume that
          -- default list. inject_url() still associates it with the MIME part.
          local url = create_web_url(task:get_mempool(), value)
          if url then
            seen[value] = true
            task:inject_url(url, part)
            extracted[#extracted + 1] = value
          end
        end
      end
    end
  end

  if #extracted > 0 then
    return true, 1.0, extracted
  end
  return false
end

exports.callback = svg_url_extraction

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "prefilter",
  callback = svg_url_extraction,
  -- Prefilters run in descending priority. URL heuristics use the default (0),
  -- so extraction at 9 makes injected URLs visible before those rules execute.
  priority = 9,
  score = 0.0,
  group = "url",
  description = "Web URL extracted from an SVG MIME part",
})

return exports
