-- MSG-1868: expose HTTP(S) URLs from List-Unsubscribe headers to the
-- existing URL phishing and lookalike-domain rules.

local rspamd_url = require "rspamd_url"

local exports = {}
local SYMBOL = "HEADER_URL_EXTRACTION"
local MAX_URLS = 100

local function trim(value)
  return tostring(value or ""):match("^%s*(.-)%s*$") or ""
end

function exports.extract_urls(header_value)
  local urls = {}
  local seen = {}

  -- RFC 2369 list command URLs are enclosed in angle brackets. Restricting
  -- extraction to that form avoids promoting unrelated header text to URLs.
  for candidate in tostring(header_value or ""):gmatch("<([^<>]*)>") do
    local value = trim(candidate)
    if value:lower():match("^https?://") and not seen[value] then
      seen[value] = true
      urls[#urls + 1] = value
      if #urls >= MAX_URLS then
        break
      end
    end
  end

  return urls
end

local function header_url_extraction(task)
  local header_value = task:get_header("List-Unsubscribe")
  local injected = 0

  for _, value in ipairs(exports.extract_urls(header_value)) do
    local url = rspamd_url.create(task:get_mempool(), value)
    if url then
      task:inject_url(url)
      injected = injected + 1
    end
  end

  if injected > 0 then
    return true, 1.0, { "count=" .. injected }
  end
  return false
end

exports.callback = header_url_extraction

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "prefilter",
  callback = header_url_extraction,
  priority = 9,
  score = 0.0,
  group = "url",
  description = "HTTP(S) URLs extracted from the List-Unsubscribe header",
})

-- URL heuristics must run after header URLs have been injected.
rspamd_config:register_dependency("PHISH_URL_HEURISTIC", SYMBOL)
rspamd_config:register_dependency("LOOKALIKE_DOMAIN", SYMBOL)

return exports
