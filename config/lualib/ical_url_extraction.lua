-- MSG-1860: extract phishing URLs from iCalendar MIME parts before URL rules run.

local rspamd_url = require "rspamd_url"
local rspamd_util = require "rspamd_util"

local exports = {}
local SYMBOL = "ICAL_URL_EXTRACTION"
local MAX_CALENDAR_BYTES = 1024 * 1024
local MAX_URLS = 100

local url_properties = {
  URL = true,
  DESCRIPTION = true,
  ATTACH = true,
}

local function trim(value)
  return (tostring(value or ""):match("^%s*(.-)%s*$") or "")
end

local function looks_like_ical(value)
  return tostring(value or ""):upper():find("BEGIN:VCALENDAR", 1, true) ~= nil
end

local function safe_decode(decoder, value)
  local ok, decoded = pcall(decoder, tostring(value or ""))
  if ok and decoded then
    return tostring(decoded)
  end
  return nil
end

local function decoded_part_content(part)
  local content = part.get_content and tostring(part:get_content() or "") or ""
  if looks_like_ical(content) then
    return content
  end

  local raw_content = part.get_raw_content and tostring(part:get_raw_content() or "") or content
  local cte = part.get_cte and string.lower(trim(part:get_cte())) or ""
  local decoded

  if cte == "base64" then
    decoded = safe_decode(rspamd_util.decode_base64, raw_content)
  elseif cte == "quoted-printable" then
    decoded = safe_decode(rspamd_util.decode_qp, raw_content)
  else
    decoded = raw_content
  end

  if decoded and looks_like_ical(decoded) then
    return decoded
  end
  return nil
end

local function unfold_lines(content)
  content = tostring(content or "")
    :gsub("\r\n", "\n")
    :gsub("\r", "\n")
    :gsub("\v", "\n")
    :gsub("\f", "\n")

  local lines = {}
  for line in (content .. "\n"):gmatch("(.-)\n") do
    if line:match("^[ \t]") and #lines > 0 then
      lines[#lines] = lines[#lines] .. line:sub(2)
    else
      lines[#lines + 1] = line
    end
  end
  return lines
end

local function decode_property_value(name_and_params, value)
  if name_and_params:upper():find("ENCODING%s*=%s*\"?QUOTED%-PRINTABLE\"?") then
    return safe_decode(rspamd_util.decode_qp, value) or value
  end
  return value
end

-- Extract web URLs from text when Rspamd's native parser does not recognize
-- the scheme or TLD.
local function extract_urls_from_text(text)
  local urls = {}
  for url in tostring(text or ""):gmatch("[%a][%w+%.%-]*://[%w%.%-%_%%:/?=&~#+]+") do
    local scheme = url:match("^([^:]+)")
    scheme = scheme and scheme:lower() or ""
    if scheme == "http" or scheme == "https" or scheme == "ws" or scheme == "wss" then
      urls[#urls + 1] = url
    end
  end
  return urls
end

local function create_web_url(mempool, value)
  local url = rspamd_url.create(mempool, value)
  if url then
    return url
  end

  -- Rspamd 3.10 cannot create URL objects for WebSocket schemes. Map them to
  -- their equivalent HTTP transports before injection into task:get_urls().
  local scheme, remainder = tostring(value):match("^([Ww][Ss][Ss]?)://(.*)$")
  if scheme then
    local compatible_scheme = scheme:lower() == "wss" and "https" or "http"
    return rspamd_url.create(mempool, compatible_scheme .. "://" .. remainder)
  end
  return nil
end

local function append_urls(value, mempool, urls, seen)
  -- First try rspamd_url.all (works for real TLDs)
  local parsed_urls = rspamd_url.all(mempool, tostring(value or "")) or {}
  for _, url in ipairs(parsed_urls) do
    local normalized = tostring(url)
    if normalized ~= "" and not seen[normalized] then
      seen[normalized] = true
      urls[#urls + 1] = url
      if #urls >= MAX_URLS then
        return true
      end
    end
  end

  -- Fallback: string-based extraction for reserved TLDs (.example, .test)
  -- and WebSocket schemes that rspamd_url.all() does not recognize. Always run
  -- it because one property can contain both a native HTTP URL and a ws(s) URL.
  for _, url_str in ipairs(extract_urls_from_text(value)) do
    if not seen[url_str] then
      -- Create URL object if possible, otherwise use the string
      local url_obj = create_web_url(mempool, url_str)
      if url_obj then
        local normalized = tostring(url_obj)
        if normalized ~= "" and not seen[normalized] then
          seen[url_str] = true
          seen[normalized] = true
          urls[#urls + 1] = url_obj
        end
      else
        -- For reserved TLDs, create a fake URL-like table
        seen[url_str] = true
        urls[#urls + 1] = {
          _url = url_str,
          get_host = function() return url_str:match("^%a+://([^/:]+)") or "" end,
          get_tld = function() return url_str:match("(%.[^.]+)$") or "" end,
          get_query = function() return url_str:match("%?(.*)") or "" end,
          get_path = function() return url_str:match("://[^/]+(/[^?]*)") or "/" end,
        }
      end
      if #urls >= MAX_URLS then
        return true
      end
    end
  end
  return false
end

function exports.extract_url_objects(content, mempool)
  local urls = {}
  local seen = {}
  local event_depth = 0

  for _, line in ipairs(unfold_lines(content)) do
    local name_and_params, value = line:match("^([^:]+):(.*)$")
    if name_and_params then
      local property_name = trim(name_and_params:match("^([^;]+)")):upper()
      local normalized_value = trim(value):upper()

      if property_name == "BEGIN" and normalized_value == "VEVENT" then
        event_depth = event_depth + 1
      elseif property_name == "END" and normalized_value == "VEVENT" then
        event_depth = math.max(0, event_depth - 1)
      elseif event_depth > 0 and url_properties[property_name] then
        value = decode_property_value(name_and_params, value)
        if append_urls(value, mempool, urls, seen) then
          break
        end
      end
    end
  end

  return urls
end

function exports.extract_urls(content, mempool)
  local values = {}
  for _, url in ipairs(exports.extract_url_objects(content, mempool)) do
    values[#values + 1] = tostring(url)
  end
  return values
end

local function is_calendar_part(part)
  if not part.get_type then
    return false
  end
  local mtype, subtype = part:get_type()
  return string.lower(tostring(mtype or "")) == "text" and
      string.lower(tostring(subtype or "")) == "calendar" or
      string.lower(tostring(mtype or "")) == "application" and
      string.lower(tostring(subtype or "")) == "calendar"
end

local function ical_url_extraction(task)
  local extracted = 0
  local seen = {}

  for _, part in ipairs(task:get_parts() or {}) do
    if is_calendar_part(part) then
      local content = decoded_part_content(part)
      if content and #content <= MAX_CALENDAR_BYTES then
        for _, url in ipairs(exports.extract_url_objects(content, task:get_mempool())) do
          local normalized = tostring(url)
          if not seen[normalized] then
            seen[normalized] = true
            task:inject_url(url, part)
            extracted = extracted + 1
            if extracted >= MAX_URLS then
              break
            end
          end
        end
      end
    end
    if extracted >= MAX_URLS then
      break
    end
  end

  if extracted > 0 then
    return true, 1.0, { "count=" .. extracted }
  end
  return false
end

exports.callback = ical_url_extraction

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "prefilter",
  callback = ical_url_extraction,
  score = 0.0,
  group = "url",
  description = "URLs extracted from iCalendar event properties",
})

-- URL heuristics must run after the iCalendar URLs have been injected.
rspamd_config:register_dependency("PHISH_URL_HEURISTIC", SYMBOL)
rspamd_config:register_dependency("LOOKALIKE_DOMAIN", SYMBOL)

return exports
