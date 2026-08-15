-- MSG-1875: expose HTTP(S) URLs hidden as base64 text in HTML bodies to
-- Rspamd's phishing and lookalike-domain rules.

local rspamd_url = require "rspamd_url"
local rspamd_util = require "rspamd_util"
-- rspamd_logger is available in live Rspamd but not in unit tests.
local rspamd_logger = package.loaded["rspamd_logger"]

local exports = {}
local SYMBOL = "BASE64_URL_EXTRACTION"
local MAX_CANDIDATES = 5
local MAX_DECODED_BYTES = 10 * 1024
local MAX_ENCODED_BYTES = math.ceil(MAX_DECODED_BYTES / 3) * 4

local function trim_token(value)
  value = tostring(value or "")
  value = value:gsub("^[%(%[%{%<\"'`]+", "")
  return (value:gsub("[%)%]%}%>\"'`,;:%.!?]+$", ""))
end

function exports.is_candidate(value)
  value = tostring(value or "")
  if #value < 20 or #value > MAX_ENCODED_BYTES then
    return false
  end

  local payload, padding = value:match("^([A-Za-z0-9+/]+)(=*)$")
  return payload ~= nil and #payload >= 20 and #padding <= 2
end

local function is_data_image_token(value)
  return tostring(value or ""):lower():match("^data:image/[^,]*,") ~= nil
end

function exports.extract_urls(content)
  local urls = {}
  local seen = {}

  for raw_candidate in tostring(content or ""):gmatch("[Hh][Tt][Tt][Pp][Ss]?://[^%s<>\"'`]+") do
    local candidate = raw_candidate:gsub("[%]%)}>,;%.!?]+$", "")
    if candidate ~= "" and not seen[candidate] then
      seen[candidate] = true
      urls[#urls + 1] = candidate
    end
  end

  return urls
end

local function decoded_candidate(candidate)
  if not exports.is_candidate(candidate) then
    return nil
  end

  local ok, decoded = pcall(rspamd_util.decode_base64, candidate)
  if not ok or decoded == nil then
    return nil
  end

  decoded = tostring(decoded)
  if #decoded > MAX_DECODED_BYTES then
    return nil
  end
  return decoded
end

local function base64_url_extraction(task)
  local candidate_count = 0
  local extracted = {}
  local seen = {}

  for _, part in ipairs(task:get_text_parts() or {}) do
    if part.is_html and part:is_html() and part.get_content then
      local content = tostring(part:get_content() or "")
      for raw_token in content:gmatch("%S+") do
        local token = trim_token(raw_token)
        if not is_data_image_token(token) and exports.is_candidate(token) then
          candidate_count = candidate_count + 1
          local decoded = decoded_candidate(token)
          if decoded then
            for _, value in ipairs(exports.extract_urls(decoded)) do
              if not seen[value] then
                local url = rspamd_url.create(task:get_mempool(), value)
                if url then
                  local normalized = tostring(url)
                  if normalized ~= "" and not seen[normalized] then
                    seen[value] = true
                    seen[normalized] = true
                    task:inject_url(url)
                    extracted[#extracted + 1] = value
                  end
                end
              end
            end
          end

          if candidate_count >= MAX_CANDIDATES then
            break
          end
        end
      end
    end

    if candidate_count >= MAX_CANDIDATES then
      break
    end
  end

  if #extracted > 0 then
    return true, 1.0, extracted
  end
  return false
end

exports.callback = base64_url_extraction

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "prefilter",
  callback = base64_url_extraction,
  priority = 9,
  score = 0.0,
  group = "url",
  description = "HTTP(S) URL extracted from base64 text in an HTML body",
})

-- URL heuristics must run after hidden URLs have been injected.
rspamd_config:register_dependency("PHISH_URL_HEURISTIC", SYMBOL)
rspamd_config:register_dependency("LOOKALIKE_DOMAIN", SYMBOL)

return exports
