local module_dir = os.getenv("SVG_URL_EXTRACTION_LUA_PATH") or "config/lualib"
package.path = module_dir .. "/?.lua;" .. package.path

local registered_symbol
_G.rspamd_config = {
  register_symbol = function(_, definition)
    registered_symbol = definition
    return definition.name
  end,
}

local function decode_base64(value)
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  value = tostring(value or ""):gsub("[^" .. alphabet .. "=]", "")
  local bits = value:gsub(".", function(character)
    if character == "=" then
      return ""
    end
    local index = alphabet:find(character, 1, true)
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

local function parsed_url(value)
  local normalized = value
  if normalized:match("^//") then
    normalized = "https:" .. normalized
  end
  if not normalized:lower():match("^https?://") then
    return nil
  end
  return setmetatable({ value = normalized }, {
    __tostring = function(url)
      return url.value
    end,
  })
end

package.preload["rspamd_url"] = function()
  return {
    create = function(_, value)
      return parsed_url(value)
    end,
  }
end

local extraction = require "svg_url_extraction"

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function mime_part(content_type, content, cte)
  local main_type, subtype = content_type:match("^([^/]+)/(.+)$")
  local content_reads = 0
  local part = {
    get_type = function()
      return main_type, subtype
    end,
    get_content = function()
      content_reads = content_reads + 1
      return content
    end,
    get_cte = function()
      return cte or "7bit"
    end,
    content_reads = function()
      return content_reads
    end,
  }
  return part
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
        value = tostring(url),
        part = part,
      }
    end,
  }

  local matched, multiplier, options = registered_symbol.callback(task)
  return {
    matched = matched or false,
    multiplier = multiplier,
    options = options,
    injected = injected,
  }
end

local function assert_extracted(svg, expected_url, label, cte)
  local part = mime_part("image/svg+xml", svg, cte)
  local result = scan({ part })
  eq(result.matched, true, label .. " symbol")
  eq(result.multiplier, 1.0, label .. " multiplier")
  eq(#result.injected, 1, label .. " injected count")
  eq(result.injected[1].value, expected_url, label .. " URL")
  eq(result.injected[1].part, part, label .. " MIME part association")
end

assert(registered_symbol, "SVG_URL_EXTRACTION must be registered")
eq(registered_symbol.name, "SVG_URL_EXTRACTION", "registered symbol name")
eq(registered_symbol.type, "prefilter", "registered symbol type")
eq(registered_symbol.score, 0.0, "registered symbol score")
assert((registered_symbol.priority or 0) > 0, "SVG_URL_EXTRACTION must run before URL heuristic prefilters")

assert_extracted(
  '<svg><foreignObject data="https://microsoft.security.evil.example/verify"></foreignObject></svg>',
  "https://microsoft.security.evil.example/verify",
  "foreignObject data"
)

assert_extracted(
  "<svg><image href='https://micros0ft.evil.example/image.png'/></svg>",
  "https://micros0ft.evil.example/image.png",
  "image href"
)

assert_extracted(
  '<svg xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="https://paypal.security.evil.example/pixel"/></svg>',
  "https://paypal.security.evil.example/pixel",
  "image xlink href"
)

assert_extracted(
  '<svg><use href="https://paypal.security.evil.example/sprite.svg#login"/></svg>',
  "https://paypal.security.evil.example/sprite.svg#login",
  "use href"
)

assert_extracted(
  '<svg><a href="https://amazon.security.evil.example/login"><text>Open</text></a></svg>',
  "https://amazon.security.evil.example/login",
  "anchor href"
)

assert_extracted(
  '<svg><foreignObject data="ws://paypal.security.evil.example/socket"></foreignObject></svg>',
  "http://paypal.security.evil.example/socket",
  "WebSocket foreignObject data"
)

assert_extracted(
  '<svg><a href="wss://micros0ft.evil.example/session"><text>Connect</text></a></svg>',
  "https://micros0ft.evil.example/session",
  "secure WebSocket anchor href"
)

local no_url = scan({ mime_part("image/svg+xml", '<svg><use href="#local-icon"/></svg>') })
eq(no_url.matched, false, "SVG with no network URLs")
eq(#no_url.injected, 0, "SVG with no network URLs injected count")

local commented_url = scan({ mime_part(
  "image/svg+xml",
  '<svg><!-- <foreignObject data="https://microsoft.security.evil.example/comment"/> --><text>No URL</text></svg>'
) })
eq(commented_url.matched, false, "URL-bearing markup inside an SVG comment")
eq(#commented_url.injected, 0, "SVG comment injected count")

local non_svg_part = mime_part(
  "application/xml",
  '<svg><foreignObject data="https://microsoft.security.evil.example/verify"/></svg>'
)
local non_svg = scan({ non_svg_part })
eq(non_svg.matched, false, "non-SVG MIME part")
eq(#non_svg.injected, 0, "non-SVG injected count")
eq(non_svg_part.content_reads(), 0, "non-SVG content must not be read")

local encoded_svg = "PHN2Zz48Zm9yZWlnbk9iamVjdCBkYXRhPSJodHRwczovL21pY3Jvc29mdC5zZWN1cml0eS5ldmlsLmV4YW1wbGUvYmFzZTY0Ii8+PC9zdmc+"
assert_extracted(
  encoded_svg,
  "https://microsoft.security.evil.example/base64",
  "base64 SVG",
  "base64"
)

-- Rspamd's real mime_part:get_content() already returns decoded parsed_data even
-- when the transfer encoding is base64. Do not decode a second time.
assert_extracted(
  '<svg><foreignObject data="https://microsoft.security.evil.example/already-decoded"/></svg>',
  "https://microsoft.security.evil.example/already-decoded",
  "already-decoded base64 MIME part",
  "base64"
)

local duplicate = scan({ mime_part(
  "image/svg+xml",
  '<svg><image href="https://evil.example/same"/><use href="https://evil.example/same"/></svg>'
) })
eq(duplicate.matched, true, "duplicate URL symbol")
eq(#duplicate.injected, 1, "duplicate URL is injected once")

eq(extraction.is_svg_type("IMAGE", "SVG+XML"), true, "case-insensitive SVG MIME type")
eq(extraction.is_svg_type("image", "png"), false, "non-SVG image type")

print("svg_url_extraction_test: PASS")
