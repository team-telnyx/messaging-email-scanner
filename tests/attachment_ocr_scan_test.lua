package.loaded["rspamd_logger"] = {
  infox = function() end,
  warnx = function() end,
  errx = function() end,
}

local module_dir = os.getenv("ATTACHMENT_OCR_SCAN_LUA_PATH") or "config/lualib"
package.path = module_dir .. "/?.lua;" .. package.path

local symbols = {}
local dependencies = {}
_G.rspamd_config = {
  get_all_opt = function(_, name)
    if name == "ocr" then
      return {
        tesseract_bin = "/usr/bin/tesseract",
        timeout_bin = "/usr/bin/timeout",
        language = "eng",
        timeout_ms = 400,
        max_output_chars = 8192,
      }
    end
    return nil
  end,
  register_symbol = function(_, definition)
    symbols[definition.name] = definition
    return definition.name
  end,
  register_dependency = function(_, symbol, dependency)
    dependencies[symbol] = dependencies[symbol] or {}
    dependencies[symbol][dependency] = true
  end,
}

package.preload["rspamd_util"] = function()
  return {
    random_hex = function()
      return "unit-test"
    end,
    unlink = function() end,
  }
end

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
      if tostring(value):lower():match("^https?://") then
        return url_object(value)
      end
      return nil
    end,
  }
end

local attachment_ocr = require "attachment_ocr_scan"

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function contains(values, expected)
  for _, value in ipairs(values or {}) do
    if value == expected then
      return true
    end
  end
  return false
end

local function mime_part(content_type, size, attachment, content)
  local main_type, subtype = content_type:match("^([^/]+)/(.+)$")
  local content_reads = 0
  return {
    get_type = function()
      return main_type, subtype
    end,
    get_length = function()
      return size
    end,
    is_attachment = function()
      return attachment == true
    end,
    get_content = function()
      content_reads = content_reads + 1
      return content or "image bytes"
    end,
    content_reads = function()
      return content_reads
    end,
  }
end

local function scan(parts, recognized_by_part, existing_urls)
  local attempted = {}
  local injected = {}
  attachment_ocr.ocr_part = function(part)
    attempted[#attempted + 1] = part
    local result = recognized_by_part and recognized_by_part[part]
    if type(result) == "table" then
      return result[1], result[2]
    end
    return result or ""
  end

  local task = {
    get_parts = function()
      return parts
    end,
    get_urls = function()
      local urls = {}
      for _, value in ipairs(existing_urls or {}) do
        urls[#urls + 1] = url_object(value)
      end
      return urls
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

  local matched, multiplier, options = symbols.ATTACHMENT_OCR_SCAN.callback(task)
  return {
    matched = matched or false,
    multiplier = multiplier,
    options = options or {},
    attempted = attempted,
    injected = injected,
  }
end

local symbol = symbols.ATTACHMENT_OCR_SCAN
assert(symbol, "ATTACHMENT_OCR_SCAN must be registered")
eq(symbol.type, "prefilter", "registered symbol type")
eq(symbol.score, 0.0, "registered symbol score")
eq(symbol.group, "url", "registered symbol group")
eq(dependencies.PHISH_URL_HEURISTIC.ATTACHMENT_OCR_SCAN, true, "phishing heuristic dependency")
eq(dependencies.LOOKALIKE_DOMAIN.ATTACHMENT_OCR_SCAN, true, "lookalike dependency")

-- Supported image attachments are OCRed and recognized URLs are associated with
-- the originating MIME part before being injected into the task.
local png = mime_part("image/png", 2048, true)
local jpeg = mime_part("image/jpeg", 4096, true)
local gif = mime_part("image/gif", 8192, true)
local result = scan({ png, jpeg, gif }, {
  [png] = "Scan https://micros0ft.evil.example/verify now",
  [jpeg] = "Open http://paypal.security.evil.example/login",
  [gif] = "No URL in this screenshot",
})
eq(result.matched, true, "eligible attachments emit informational symbol")
eq(result.multiplier, 1.0, "informational symbol multiplier")
eq(#result.attempted, 3, "all supported image attachments are OCRed")
eq(#result.injected, 2, "HTTP(S) URLs are injected")
eq(result.injected[1].value, "https://micros0ft.evil.example/verify", "PNG OCR URL")
eq(result.injected[1].part, png, "PNG MIME part association")
eq(result.injected[2].value, "http://paypal.security.evil.example/login", "JPEG OCR URL")
eq(result.injected[2].part, jpeg, "JPEG MIME part association")
assert(contains(result.options, "attachments=3"), "attempt count must be observable")
assert(contains(result.options, "urls=2"), "injected URL count must be observable")

-- Inline images, unsupported images, and non-image attachments are ignored and
-- their content is never read.
local inline_png = mime_part("image/png", 1000, false)
local bmp = mime_part("image/bmp", 1000, true)
local text = mime_part("text/plain", 1000, true)
result = scan({ inline_png, bmp, text }, {})
eq(result.matched, false, "no eligible attachment")
eq(#result.attempted, 0, "ignored parts are not OCRed")
eq(inline_png.content_reads(), 0, "inline image content is not read")
eq(bmp.content_reads(), 0, "unsupported image content is not read")
eq(text.content_reads(), 0, "non-image content is not read")

-- The 1 MiB limit is inclusive and applies to decoded attachment bytes.
local at_limit = mime_part("IMAGE/PNG", 1024 * 1024, true)
local over_limit = mime_part("image/jpeg", 1024 * 1024 + 1, true)
result = scan({ at_limit, over_limit }, {
  [at_limit] = "https://evil.example/within-limit",
  [over_limit] = "https://evil.example/too-large",
})
eq(#result.attempted, 1, "only attachment at size limit is OCRed")
eq(result.attempted[1], at_limit, "1 MiB attachment is eligible")
eq(#result.injected, 1, "oversized attachment URL is not injected")
eq(result.injected[1].value, "https://evil.example/within-limit", "size-limit URL")

-- Duplicate OCR URLs and URLs already present in the task are not reinjected.
local duplicate = mime_part("image/gif", 100, true)
result = scan({ duplicate }, {
  [duplicate] = "https://evil.example/same https://evil.example/same https://evil.example/existing",
}, { "https://evil.example/existing" })
eq(#result.injected, 1, "duplicate and existing URLs are suppressed")
eq(result.injected[1].value, "https://evil.example/same", "unique OCR URL")

-- OCR attempts remain visible even when no text is found or the engine fails.
local blank = mime_part("image/png", 100, true)
local failed = mime_part("image/jpeg", 100, true)
result = scan({ blank, failed }, {
  [blank] = "",
  [failed] = { nil, "timeout" },
})
eq(result.matched, true, "attempted OCR emits symbol without URLs")
eq(#result.attempted, 2, "blank and failed OCR are both attempted")
eq(#result.injected, 0, "blank and failed OCR inject no URLs")
assert(contains(result.options, "attachments=2"), "failed attempts are counted")
assert(contains(result.options, "urls=0"), "zero URL count is observable")

local parsed = attachment_ocr.extract_urls(
  "Open (https://evil.example/path), then http://evil.example/two. Ignore ftp://evil.example/file"
)
eq(#parsed, 2, "URL parser only returns HTTP(S) URLs")
eq(parsed[1], "https://evil.example/path", "HTTPS URL delimiter trimming")
eq(parsed[2], "http://evil.example/two", "HTTP URL delimiter trimming")

print("attachment_ocr_scan_test: PASS")
