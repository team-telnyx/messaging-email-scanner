local module_dir = os.getenv("ICAL_URL_EXTRACTION_LUA_PATH") or "config/lualib"
package.path = module_dir .. "/?.lua;" .. package.path

local symbols = {}
local dependencies = {}
_G.rspamd_config = {
  register_symbol = function(_, definition)
    symbols[definition.name] = definition
    return definition.name
  end,
  register_dependency = function(_, symbol, dependency)
    dependencies[symbol] = dependencies[symbol] or {}
    dependencies[symbol][dependency] = true
  end,
}

local base64_marker = "QkFTRTY0X0lDQUw="
local quoted_printable_marker = "BEGIN=3AVCALENDAR=0ABEGIN=3AVEVENT"
local base64_calendar = table.concat({
  "BEGIN:VCALENDAR",
  "VERSION:2.0",
  "URL:https://outside.evil.example/ignored",
  "BEGIN:VEVENT",
  "URL:https://paypal.evil.example/enroll/verify",
  "DESCRIPTION:Review https://evil.example/paypal/login and",
  " https://micros0ft.phishing.test/benefits",
  "ATTACH;FMTTYPE=application/pdf:https://micros0ft.phishing.test/benefits.pdf",
  "END:VEVENT",
  "END:VCALENDAR",
}, "\r\n")
local quoted_printable_calendar = table.concat({
  "BEGIN:VCALENDAR",
  "BEGIN:VEVENT",
  "DESCRIPTION;ENCODING=QUOTED-PRINTABLE:Open https=3A//paypal.evil.example/qp",
  "END:VEVENT",
  "END:VCALENDAR",
}, "\r\n")

local decode_base64_calls = 0
local decode_qp_calls = 0
package.preload["rspamd_util"] = function()
  return {
    decode_base64 = function(value)
      decode_base64_calls = decode_base64_calls + 1
      if tostring(value) == base64_marker then
        return base64_calendar
      end
      error("unexpected base64 input")
    end,
    decode_qp = function(value)
      decode_qp_calls = decode_qp_calls + 1
      value = tostring(value)
      if value == quoted_printable_marker then
        return quoted_printable_calendar
      end
      return (value:gsub("=3[Aa]", ":"):gsub("=0[Dd]", "\r"):gsub("=0[Aa]", "\n"))
    end,
  }
end

local function url_object(value)
  return setmetatable({}, {
    __tostring = function()
      return value
    end,
  })
end

package.preload["rspamd_url"] = function()
  return {
    all = function(_, value)
      local urls = {}
      for candidate in tostring(value or ""):gmatch("https?://[^%s<>\"']+") do
        local normalized = candidate:gsub("[%.,;!%)%]%}]+$", "")
        urls[#urls + 1] = url_object(normalized)
      end
      return urls
    end,
  }
end

local extraction = require "ical_url_extraction"

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function mime_part(mtype, subtype, content, raw_content, cte)
  return {
    get_type = function()
      return mtype, subtype
    end,
    get_content = function()
      return content
    end,
    get_raw_content = function()
      return raw_content or content
    end,
    get_cte = function()
      return cte
    end,
  }
end

local function scan(parts)
  local injected = {}
  local task = {
    get_parts = function()
      return parts
    end,
    get_mempool = function()
      return {}
    end,
    inject_url = function(_, url, part)
      injected[#injected + 1] = {
        url = tostring(url),
        part = part,
      }
    end,
  }

  local matched, multiplier, options = symbols.ICAL_URL_EXTRACTION.callback(task)
  return {
    matched = matched or false,
    multiplier = multiplier,
    options = options or {},
    injected = injected,
  }
end

local function injected_set(result)
  local values = {}
  for _, injected in ipairs(result.injected) do
    values[injected.url] = (values[injected.url] or 0) + 1
  end
  return values
end

local symbol = symbols.ICAL_URL_EXTRACTION
assert(symbol, "ICAL_URL_EXTRACTION must be registered")
eq(symbol.type, "prefilter", "registered symbol type")
eq(symbol.score, 0.0, "registered symbol score")
eq(symbol.group, "url", "registered symbol group")
eq(dependencies.PHISH_URL_HEURISTIC.ICAL_URL_EXTRACTION, true, "phishing heuristic dependency")
eq(dependencies.LOOKALIKE_DOMAIN.ICAL_URL_EXTRACTION, true, "lookalike dependency")

-- Base64 MIME content is decoded when Rspamd has not already decoded the part.
local encoded_part = mime_part("text", "calendar", base64_marker, base64_marker, "base64")
local result = scan({ encoded_part })
local values = injected_set(result)
eq(result.matched, true, "base64 calendar match")
eq(result.multiplier, 1.0, "base64 calendar multiplier")
eq(result.options[1], "count=4", "base64 URL count option")
eq(#result.injected, 4, "base64 unique URL count")
eq(values["https://paypal.evil.example/enroll/verify"], 1, "URL property extraction")
eq(values["https://evil.example/paypal/login"], 1, "DESCRIPTION URL extraction")
eq(values["https://micros0ft.phishing.test/benefits"], 1, "folded DESCRIPTION URL extraction")
eq(values["https://micros0ft.phishing.test/benefits.pdf"], 1, "ATTACH URL extraction")
eq(values["https://outside.evil.example/ignored"], nil, "URL outside VEVENT ignored")
eq(result.injected[1].part, encoded_part, "injected URL retains MIME part")
assert(decode_base64_calls > 0, "base64 fallback decoder must be used")

-- Parsed content wins when Rspamd has already decoded a base64 MIME part.
local calls_before_decoded_scan = decode_base64_calls
result = scan({ mime_part("text", "calendar", base64_calendar, base64_marker, "base64") })
eq(result.matched, true, "already-decoded base64 calendar match")
eq(#result.injected, 4, "already-decoded base64 URL count")
eq(decode_base64_calls, calls_before_decoded_scan, "already-decoded content is not decoded twice")

-- MIME-level and property-level quoted-printable content are decoded.
result = scan({ mime_part("text", "calendar", quoted_printable_marker, quoted_printable_marker, "quoted-printable") })
values = injected_set(result)
eq(result.matched, true, "quoted-printable calendar match")
eq(values["https://paypal.evil.example/qp"], 1, "quoted-printable DESCRIPTION URL extraction")
assert(decode_qp_calls >= 2, "MIME and property quoted-printable decoders must be used")

-- Duplicate URLs across URL, DESCRIPTION, and ATTACH fields are injected once.
local duplicate_calendar = table.concat({
  "BEGIN:VCALENDAR",
  "BEGIN:VEVENT",
  "URL:https://paypal.evil.example/duplicate",
  "DESCRIPTION:Open https://paypal.evil.example/duplicate",
  "ATTACH:https://paypal.evil.example/duplicate",
  "END:VEVENT",
  "END:VCALENDAR",
}, "\n")
result = scan({ mime_part("text", "calendar", duplicate_calendar, duplicate_calendar, "8bit") })
eq(result.matched, true, "duplicate calendar match")
eq(#result.injected, 1, "duplicate URL injected once")

-- Calendar matching is case-insensitive and includes application/calendar.
local lower_calendar = table.concat({
  "begin:vcalendar",
  "begin:vevent",
  "attach:https://evil.example/paypal/file",
  "end:vevent",
  "end:vcalendar",
}, "\n")
result = scan({ mime_part("APPLICATION", "CALENDAR", lower_calendar, lower_calendar, "8bit") })
eq(result.matched, true, "application/calendar match")
eq(#result.injected, 1, "case-insensitive property extraction")

-- Non-calendar parts and calendar events without URL-bearing properties are ignored.
result = scan({
  mime_part("text", "plain", base64_calendar, base64_calendar, "8bit"),
  mime_part("text", "calendar", "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Team sync\nEND:VEVENT\nEND:VCALENDAR", nil, "8bit"),
})
eq(result.matched, false, "non-calendar and URL-free parts do not match")
eq(#result.injected, 0, "non-calendar and URL-free parts inject nothing")

-- Malformed transfer encoding must fail open without crashing the scan.
result = scan({ mime_part("text", "calendar", "not base64!", "not base64!", "base64") })
eq(result.matched, false, "malformed encoded calendar does not match")
eq(#result.injected, 0, "malformed encoded calendar injects nothing")

-- Exported parser is independently testable and returns unique URL strings.
local parsed = extraction.extract_urls(duplicate_calendar, {})
eq(#parsed, 1, "exported parser deduplicates URLs")
eq(parsed[1], "https://paypal.evil.example/duplicate", "exported parser URL")

print("ical_url_extraction_test: PASS")
