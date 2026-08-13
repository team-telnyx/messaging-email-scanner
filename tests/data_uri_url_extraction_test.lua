local module_dir = os.getenv("DATA_URI_URL_EXTRACTION_LUA_PATH") or "config/lualib"
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

local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local decode_base64_calls = 0
local function decode_base64(value)
  decode_base64_calls = decode_base64_calls + 1
  value = tostring(value or ""):gsub("[^" .. alphabet .. "=]", "")
  local bits = value:gsub(".", function(character)
    if character == "=" then
      return ""
    end
    local index = alphabet:find(character, 1, true)
    if not index then
      error("invalid base64")
    end
    local result = ""
    local number = index - 1
    for bit = 6, 1, -1 do
      result = result .. (number % 2 ^ bit - number % 2 ^ (bit - 1) > 0 and "1" or "0")
    end
    return result
  end)
  return bits:gsub("%d%d%d?%d?%d?%d?%d?%d?", function(byte)
    if #byte ~= 8 then
      return ""
    end
    local number = 0
    for index = 1, 8 do
      if byte:sub(index, index) == "1" then
        number = number + 2 ^ (8 - index)
      end
    end
    return string.char(number)
  end)
end

package.preload["rspamd_util"] = function()
  return {
    decode_base64 = decode_base64,
  }
end

local function url_object(value, protocol, raw)
  return setmetatable({ value = value }, {
    __index = {
      get_protocol = function()
        return protocol
      end,
      get_raw = function()
        return raw or value
      end,
      get_text = function()
        return value
      end,
    },
    __tostring = function(url)
      return url.value
    end,
  })
end

package.preload["rspamd_url"] = function()
  return {
    create = function(_, value)
      if tostring(value):lower():match("^https?://") then
        return url_object(value, value:match("^([^:]+)"))
      end
      return nil
    end,
  }
end

local extraction = require "data_uri_url_extraction"

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function data_url(value, raw)
  return url_object(value, "data", raw)
end

local function scan(urls, tags)
  local injected = {}
  local task = {
    get_urls = function()
      return urls
    end,
    get_text_parts = function()
      if not tags then
        return {}
      end
      return {
        {
          is_html = function()
            return true
          end,
          get_html = function()
            return {
              foreach_tag = function(_, requested_name, callback)
                for _, attributes in ipairs(tags) do
                  if attributes.name == requested_name then
                    callback({
                      get_attribute = function(_, attribute)
                        return attributes[attribute]
                      end,
                    })
                  end
                end
              end,
            }
          end,
        },
      }
    end,
    get_mempool = function()
      return {}
    end,
    inject_url = function(_, url)
      injected[#injected + 1] = tostring(url)
    end,
  }

  local matched, multiplier, options = symbols.DATA_URI_URL_EXTRACTION.callback(task)
  return {
    matched = matched or false,
    multiplier = multiplier,
    options = options or {},
    injected = injected,
  }
end

local symbol = symbols.DATA_URI_URL_EXTRACTION
assert(symbol, "DATA_URI_URL_EXTRACTION must be registered")
eq(symbol.type, "normal", "registered symbol type")
eq(symbol.score, 0.0, "registered symbol score")
eq(symbol.group, "url", "registered symbol group")
eq(dependencies.PHISH_URL_HEURISTIC.DATA_URI_URL_EXTRACTION, true, "phishing heuristic dependency")
eq(dependencies.LOOKALIKE_DOMAIN.DATA_URI_URL_EXTRACTION, true, "lookalike dependency")

-- Percent-encoded text/html payloads are decoded and all HTTP(S) URLs are injected.
local result = scan({
  data_url("data:text/html,%3Cscript%3Efetch(%27https%3A%2F%2Fmicros0ft.evil.example%2Fcollect%27)%3Blocation%3D%27http%3A%2F%2Fevil.example%2Fnext%3Fx%3D1%26y%3D2%27%3C%2Fscript%3E"),
})
eq(result.matched, true, "percent-encoded HTML match")
eq(result.multiplier, 1.0, "percent-encoded HTML multiplier")
eq(result.options[1], "count=2", "percent-encoded HTML count option")
eq(#result.injected, 2, "percent-encoded HTML injected count")
eq(result.injected[1], "https://micros0ft.evil.example/collect", "percent-encoded HTTPS URL")
eq(result.injected[2], "http://evil.example/next?x=1&y=2", "percent-encoded HTTP URL")

-- Rspamd 3.10 omits data: attributes from task:get_urls(), so HTML form
-- actions are also collected directly from parsed tags.
result = scan({}, {
  {
    name = "form",
    action = "data:text/html,post(%27https%3A%2F%2Fpaypa1.evil.example%2Fcollect%27)",
  },
})
eq(result.matched, true, "HTML form action match")
eq(#result.injected, 1, "HTML form action injected count")
eq(result.injected[1], "https://paypa1.evil.example/collect", "HTML form action URL")

-- Base64 and media-type parameters are supported for text/plain payloads.
local encoded = "UG9zdCB0byBodHRwczovL3BheXBhbC5ldmlsLmV4YW1wbGUvbG9naW4="
result = scan({ data_url("data:text/plain;charset=utf-8;base64," .. encoded) })
eq(result.matched, true, "base64 text match")
eq(#result.injected, 1, "base64 text injected count")
eq(result.injected[1], "https://paypal.evil.example/login", "base64 text URL")
assert(decode_base64_calls > 0, "base64 decoder must be used")

-- RFC 2397's omitted media type defaults to text/plain.
result = scan({ data_url("data:,Open%20https%3A%2F%2Fevil.example%2Fdefault") })
eq(result.matched, true, "default text/plain match")
eq(result.injected[1], "https://evil.example/default", "default text/plain URL")

-- URL text must be read from get_raw() when tostring() is normalized/truncated.
result = scan({
  data_url("data:text/html,normalized", "data:text/html,https%3A%2F%2Fraw.evil.example%2Fsubmit"),
})
eq(result.matched, true, "raw data URI match")
eq(result.injected[1], "https://raw.evil.example/submit", "raw data URI URL")

-- Duplicate embedded URLs are injected once, including across multiple data URIs.
result = scan({
  data_url("data:text/plain,https%3A%2F%2Fevil.example%2Fsame%20https%3A%2F%2Fevil.example%2Fsame"),
  data_url("data:text/html,https%3A%2F%2Fevil.example%2Fsame"),
})
eq(result.matched, true, "duplicate URL match")
eq(#result.injected, 1, "duplicate embedded URL injected once")

-- An embedded URL already present in the task is not reinjected.
result = scan({
  url_object("https://evil.example/existing", "https"),
  data_url("data:text/plain,https%3A%2F%2Fevil.example%2Fexisting"),
})
eq(result.matched, false, "existing task URL not reinjected")
eq(#result.injected, 0, "existing task URL injected count")

-- data:image and unsupported media types must not be decoded or inspected.
local calls_before_ignored = decode_base64_calls
result = scan({
  data_url("data:image/svg+xml;base64,aHR0cHM6Ly9ldmlsLmV4YW1wbGUvaW1hZ2U="),
  data_url("data:application/javascript,location%3D%27https%3A%2F%2Fevil.example%2Fscript%27"),
})
eq(result.matched, false, "image and unsupported types ignored")
eq(#result.injected, 0, "image and unsupported types inject nothing")
eq(decode_base64_calls, calls_before_ignored, "ignored data URIs are not base64 decoded")

-- The decoded payload limit is inclusive at 10 KiB and rejects larger content.
local within_limit = string.rep("a", 10240 - #" https://evil.example/within") .. " https://evil.example/within"
result = scan({ data_url("data:text/plain," .. within_limit) })
eq(result.matched, true, "10 KiB payload accepted")
eq(result.injected[1], "https://evil.example/within", "10 KiB payload URL")

local over_limit = string.rep("a", 10241) .. " https://evil.example/over"
result = scan({ data_url("data:text/plain," .. over_limit) })
eq(result.matched, false, "payload larger than 10 KiB ignored")
eq(#result.injected, 0, "oversized payload injects nothing")

-- Malformed data URIs and unrelated URL protocols fail open without a symbol.
result = scan({
  data_url("data:text/html;base64"),
  url_object("https://ordinary.example/path", "https"),
})
eq(result.matched, false, "malformed and non-data URLs ignored")
eq(#result.injected, 0, "malformed and non-data URLs inject nothing")

-- The exported parser is independently testable and strips common delimiters.
local parsed = extraction.extract_urls("fetch('https://evil.example/path'); next=\"http://evil.example/two\"")
eq(#parsed, 2, "exported URL parser count")
eq(parsed[1], "https://evil.example/path", "single-quoted URL delimiter")
eq(parsed[2], "http://evil.example/two", "double-quoted URL delimiter")

print("data_uri_url_extraction_test: PASS")
