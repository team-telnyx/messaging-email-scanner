package.loaded["rspamd_logger"] = { infox = function() end, warnx = function() end, errx = function() end }
local module_dir = os.getenv("BASE64_URL_EXTRACTION_LUA_PATH") or "config/lualib"
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

local decoded_by_candidate = {}
local decode_calls = {}
package.preload["rspamd_util"] = function()
  return {
    decode_base64 = function(candidate)
      candidate = tostring(candidate)
      decode_calls[#decode_calls + 1] = candidate
      local decoded = decoded_by_candidate[candidate]
      if decoded == false then
        error("invalid base64")
      end
      return decoded
    end,
  }
end

local function parsed_url(value)
  if not tostring(value):lower():match("^https?://") then
    return nil
  end
  return setmetatable({ value = value }, {
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

local extraction = require "base64_url_extraction"

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function html_part(content)
  return {
    is_html = function()
      return true
    end,
    get_content = function()
      return content
    end,
  }
end

local function plain_part(content)
  return {
    is_html = function()
      return false
    end,
    get_content = function()
      return content
    end,
  }
end

local function scan(parts)
  local injected = {}
  local task = {
    get_text_parts = function()
      return parts
    end,
    get_mempool = function()
      return {}
    end,
    inject_url = function(_, url, part)
      if part ~= nil then
        error("HTML text parts are not valid mime_part arguments to task:inject_url")
      end
      injected[#injected + 1] = {
        value = tostring(url),
      }
    end,
  }

  local matched, multiplier, options = symbols.BASE64_URL_EXTRACTION.callback(task)
  return {
    matched = matched or false,
    multiplier = multiplier,
    options = options or {},
    injected = injected,
  }
end

local function reset_decoder()
  decoded_by_candidate = {}
  decode_calls = {}
end

local symbol = symbols.BASE64_URL_EXTRACTION
assert(symbol, "BASE64_URL_EXTRACTION must be registered")
eq(symbol.type, "prefilter", "registered symbol type")
eq(symbol.score, 0.0, "registered symbol score")
eq(symbol.group, "url", "registered symbol group")
eq(dependencies.PHISH_URL_HEURISTIC.BASE64_URL_EXTRACTION, true, "phishing heuristic dependency")
eq(dependencies.LOOKALIKE_DOMAIN.BASE64_URL_EXTRACTION, true, "lookalike dependency")

-- A base64-looking string in visible HTML body text is decoded, and every
-- HTTP(S) URL in the decoded text is injected.
reset_decoder()
local encoded_url = "aHR0cHM6Ly9taWNyb3MwZnQtbG9naW4uZXZpbC5jb20vdmVyaWZ5"
decoded_by_candidate[encoded_url] = "Decode this URL: https://micros0ft-login.evil.com/verify"
local source_part = html_part("Copy this value into a decoder: " .. encoded_url)
local result = scan({ source_part })
eq(result.matched, true, "base64 URL match")
eq(result.multiplier, 1.0, "base64 URL multiplier")
eq(#result.injected, 1, "base64 URL injected count")
eq(result.injected[1].value, "https://micros0ft-login.evil.com/verify", "base64 decoded URL")
eq(result.options[1], "https://micros0ft-login.evil.com/verify", "base64 URL symbol option")
eq(#decode_calls, 1, "base64 decoder call count")

-- Only HTML text parts are scanned.
reset_decoder()
decoded_by_candidate[encoded_url] = "https://micros0ft-login.evil.com/plain"
result = scan({ plain_part(encoded_url) })
eq(result.matched, false, "plain-text part ignored")
eq(#result.injected, 0, "plain-text part injects nothing")
eq(#decode_calls, 0, "plain-text part is not decoded")

-- Legitimate inline image data must never be treated as hidden body text.
reset_decoder()
local image_payload = "aHR0cHM6Ly9ldmlsLmNvbS9mYWtlLWltYWdl"
decoded_by_candidate[image_payload] = "https://evil.com/fake-image"
result = scan({ html_part('<img alt="logo" src="data:image/png;base64,' .. image_payload .. '">') })
eq(result.matched, false, "data image ignored")
eq(#result.injected, 0, "data image injects nothing")
eq(#decode_calls, 0, "data image payload is not decoded")

-- Candidate matching is strict: at least 20 characters, standard base64 alphabet,
-- and padding only at the end (at most two characters).
reset_decoder()
local too_short = string.rep("A", 19)
local invalid_alphabet = "aHR0cHM6Ly9ldmlsLmNvbS-0"
local invalid_padding = "aHR0cHM6=Ly9ldmlsLmNvbQ=="
decoded_by_candidate[too_short] = "https://evil.com/short"
decoded_by_candidate[invalid_alphabet] = "https://evil.com/alphabet"
decoded_by_candidate[invalid_padding] = "https://evil.com/padding"
result = scan({ html_part(table.concat({ too_short, invalid_alphabet, invalid_padding }, " ")) })
eq(result.matched, false, "invalid candidates ignored")
eq(#decode_calls, 0, "invalid candidates are not decoded")

-- At most five base64-looking candidates are decoded across the whole message.
reset_decoder()
local candidates = {}
for index = 1, 6 do
  candidates[index] = string.rep(string.char(64 + index), 20)
  decoded_by_candidate[candidates[index]] = index == 6 and "https://evil.com/sixth" or "ordinary decoded text"
end
result = scan({ html_part(table.concat(candidates, " ")) })
eq(result.matched, false, "sixth candidate is not inspected")
eq(#result.injected, 0, "sixth candidate URL is not injected")
eq(#decode_calls, 5, "candidate decode limit")

-- The 10 KiB decoded-content ceiling is enforced even if a decoder returns more
-- data than the encoded length implies. Oversized encoded candidates are skipped
-- before calling the decoder.
reset_decoder()
local oversized_decoded = string.rep("B", 20)
decoded_by_candidate[oversized_decoded] = string.rep("x", 10241) .. " https://evil.com/oversized"
local oversized_encoded = string.rep("C", 14000)
decoded_by_candidate[oversized_encoded] = "https://evil.com/encoded-oversized"
result = scan({ html_part(oversized_decoded .. " " .. oversized_encoded) })
eq(result.matched, false, "oversized candidates ignored")
eq(#result.injected, 0, "oversized candidates inject nothing")
eq(#decode_calls, 1, "oversized encoded candidate is not decoded")

-- Decode failures and decoded content without HTTP(S) URLs fail open.
reset_decoder()
local decode_error = string.rep("D", 20)
local no_web_url = string.rep("E", 20)
decoded_by_candidate[decode_error] = false
decoded_by_candidate[no_web_url] = "ftp://evil.com/not-web"
result = scan({ html_part(decode_error .. " " .. no_web_url) })
eq(result.matched, false, "decode failures and non-web URLs ignored")
eq(#result.injected, 0, "decode failures and non-web URLs inject nothing")
eq(#decode_calls, 2, "decode failures do not stop later candidates")

-- The exported candidate validator mirrors the rule's anchored base64 policy.
eq(extraction.is_candidate(string.rep("A", 20)), true, "20-character candidate")
eq(extraction.is_candidate(string.rep("A", 19)), false, "19-character candidate")
eq(extraction.is_candidate(string.rep("A", 19) .. "="), false, "padding does not satisfy minimum payload length")
eq(extraction.is_candidate(string.rep("A", 20) .. "=="), true, "two padding characters")
eq(extraction.is_candidate(string.rep("A", 20) .. "==="), false, "three padding characters")
eq(extraction.is_candidate(string.rep("A", 10) .. "=" .. string.rep("A", 10)), false, "interior padding")

print("base64_url_extraction_test: PASS")
