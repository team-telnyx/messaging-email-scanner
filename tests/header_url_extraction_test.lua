local module_dir = os.getenv("HEADER_URL_EXTRACTION_LUA_PATH") or "config/lualib"
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

local function url_object(value)
  return setmetatable({ value = value }, {
    __tostring = function(url)
      return url.value
    end,
  })
end

package.preload["rspamd_url"] = function()
  return {
    create = function(_, value)
      if tostring(value):lower():match("^https?://[%w]" ) then
        return url_object(value)
      end
      return nil
    end,
  }
end

local extraction = require "header_url_extraction"

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function scan(header_value)
  local injected = {}
  local requested_header
  local mempool = {}
  local task = {
    get_header = function(_, name)
      requested_header = name
      return header_value
    end,
    get_mempool = function()
      return mempool
    end,
    inject_url = function(_, url)
      injected[#injected + 1] = tostring(url)
    end,
  }

  local matched, multiplier, options = symbols.HEADER_URL_EXTRACTION.callback(task)
  return {
    matched = matched or false,
    multiplier = multiplier,
    options = options or {},
    injected = injected,
    requested_header = requested_header,
  }
end

local symbol = symbols.HEADER_URL_EXTRACTION
assert(symbol, "HEADER_URL_EXTRACTION must be registered")
eq(symbol.type, "prefilter", "registered symbol type")
eq(symbol.score, 0.0, "registered symbol score")
eq(symbol.group, "url", "registered symbol group")
assert((symbol.priority or 0) > 0, "HEADER_URL_EXTRACTION must run before URL heuristic prefilters")
eq(dependencies.PHISH_URL_HEURISTIC.HEADER_URL_EXTRACTION, true, "phishing heuristic dependency")
eq(dependencies.LOOKALIKE_DOMAIN.HEADER_URL_EXTRACTION, true, "lookalike dependency")

local result = scan("<mailto:unsubscribe@example.org>, <https://paypa1.evil.com/unsubscribe?token=steal>")
eq(result.requested_header, "List-Unsubscribe", "header name")
eq(result.matched, true, "mixed List-Unsubscribe header match")
eq(result.multiplier, 1.0, "mixed List-Unsubscribe multiplier")
eq(#result.injected, 1, "mixed List-Unsubscribe injected count")
eq(result.injected[1], "https://paypa1.evil.com/unsubscribe?token=steal", "HTTPS URL injection")

result = scan(" <http://example.net/unsubscribe/one> , <HTTPS://example.net/unsubscribe/two> ")
eq(result.matched, true, "multiple HTTP URLs match")
eq(#result.injected, 2, "multiple HTTP URLs injected count")
eq(result.injected[1], "http://example.net/unsubscribe/one", "HTTP URL injection")
eq(result.injected[2], "HTTPS://example.net/unsubscribe/two", "case-insensitive HTTPS scheme")

result = scan("<https://example.net/unsubscribe>, <https://example.net/unsubscribe>")
eq(result.matched, true, "duplicate URL header match")
eq(#result.injected, 1, "duplicate URL injected once")

for _, header_value in ipairs({
  "",
  "mailto:unsubscribe@example.org",
  "<mailto:unsubscribe@example.org>",
  "<ftp://example.org/unsubscribe>",
  "https://example.org/not-angle-bracketed",
  "<not a URL>",
}) do
  result = scan(header_value)
  eq(result.matched, false, "ignored header value: " .. header_value)
  eq(#result.injected, 0, "ignored header injected count: " .. header_value)
end

result = scan(nil)
eq(result.matched, false, "missing header")
eq(#result.injected, 0, "missing header injected count")

local parsed = extraction.extract_urls("<mailto:list@example.org>, <https://example.org/a>, <http://example.org/b>")
eq(#parsed, 2, "exported parser URL count")
eq(parsed[1], "https://example.org/a", "exported parser HTTPS URL")
eq(parsed[2], "http://example.org/b", "exported parser HTTP URL")

print("header_url_extraction_test: PASS")
