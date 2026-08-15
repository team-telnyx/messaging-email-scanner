-- MSG-1877: OCR image attachments before URL phishing heuristics run.
--
-- The selective OCR plugin primarily handles image-dominant messages. This
-- symbol separately covers images explicitly sent as attachments, including QR
-- images and screenshots that a recipient is instructed to open on another
-- device.

local rspamd_url = require "rspamd_url"
local rspamd_util = require "rspamd_util"
-- rspamd_logger is available in live Rspamd but not in standalone Lua tests.
local rspamd_logger = package.loaded["rspamd_logger"]

local exports = {}
local SYMBOL = "ATTACHMENT_OCR_SCAN"
local MAX_ATTACHMENT_BYTES = 1024 * 1024

local supported_types = {
  ["image/png"] = true,
  ["image/jpeg"] = true,
  ["image/gif"] = true,
}

local ocr_options = {}
if rspamd_config.get_all_opt then
  ocr_options = rspamd_config:get_all_opt("ocr") or {}
end

local settings = {
  tesseract_bin = ocr_options.tesseract_bin or "/usr/bin/tesseract",
  timeout_bin = ocr_options.timeout_bin or "/usr/bin/timeout",
  language = ocr_options.language or "eng",
  timeout_ms = tonumber(ocr_options.timeout_ms) or 400,
  max_output_chars = tonumber(ocr_options.max_output_chars) or 8192,
}

local function warn(task, format, ...)
  if rspamd_logger and rspamd_logger.warnx then
    rspamd_logger.warnx(task, format, ...)
  end
end

local function shell_quote(value)
  return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function clean_ocr_text(text)
  text = tostring(text or ""):gsub("%z", " ")
  text = text:gsub("\r\n", "\n"):gsub("\r", "\n")
  text = text:gsub("[ \t]+", " "):gsub("\n+", "\n")
  text = text:match("^%s*(.-)%s*$") or ""
  return text:sub(1, settings.max_output_chars)
end

local function run_tesseract(part)
  local content = part:get_content()
  if content == nil then
    return nil, "attachment has no decoded content"
  end

  content = tostring(content)
  -- get_length() is used for early selection; enforce the limit again against
  -- the actual decoded bytes before writing or invoking an external process.
  if #content > MAX_ATTACHMENT_BYTES then
    return nil, "attachment exceeds 1 MiB decoded size limit"
  end

  local input_path = "/tmp/rspamd-attachment-ocr-" .. rspamd_util.random_hex(16) .. ".img"
  local handle, open_error = io.open(input_path, "wb")
  if not handle then
    return nil, "temporary file: " .. tostring(open_error)
  end

  local wrote, write_error = handle:write(content)
  handle:close()
  if not wrote then
    rspamd_util.unlink(input_path)
    return nil, "temporary file write: " .. tostring(write_error)
  end

  local timeout_seconds = math.max(settings.timeout_ms, 1) / 1000.0
  local command = string.format(
    "%s --signal=KILL %.2f %s %s stdout -l %s --psm 6 2>/dev/null",
    shell_quote(settings.timeout_bin),
    timeout_seconds,
    shell_quote(settings.tesseract_bin),
    shell_quote(input_path),
    shell_quote(settings.language)
  )

  local pipe, pipe_error = io.popen(command, "r")
  if not pipe then
    rspamd_util.unlink(input_path)
    return nil, "tesseract start: " .. tostring(pipe_error)
  end

  local output = pipe:read("*a") or ""
  local ok, why, status = pipe:close()
  rspamd_util.unlink(input_path)

  if not ok then
    if tonumber(status) == 124 or tonumber(status) == 137 then
      return nil, "timeout"
    end
    return nil, string.format("tesseract failed (%s:%s)", tostring(why), tostring(status))
  end

  return clean_ocr_text(output)
end

local function normalized_type(value)
  return string.lower(tostring(value or ""))
end

local function is_image_attachment(part)
  if not part or not part.get_type or not part.get_length or not part.is_attachment then
    return false
  end

  local attachment_ok, attachment = pcall(part.is_attachment, part)
  if not attachment_ok or not attachment then
    return false
  end

  local type_ok, main_type, subtype = pcall(part.get_type, part)
  if not type_ok then
    return false
  end
  local content_type = normalized_type(main_type) .. "/" .. normalized_type(subtype)
  if not supported_types[content_type] then
    return false
  end

  local length_ok, length = pcall(part.get_length, part)
  length = length_ok and tonumber(length) or nil
  return length ~= nil and length >= 0 and length <= MAX_ATTACHMENT_BYTES
end

function exports.extract_urls(text)
  local urls = {}
  local seen = {}

  for candidate in tostring(text or ""):gmatch("[%a][%w+%.%-]*://[^%s<>\"'`]+") do
    local scheme = string.lower(candidate:match("^([^:]+)") or "")
    if scheme == "http" or scheme == "https" then
      local value = candidate:gsub("[%]%)}>,;%.!?]+$", "")
      if value ~= "" and not seen[value] then
        seen[value] = true
        urls[#urls + 1] = value
      end
    end
  end

  return urls
end

exports.ocr_part = run_tesseract
exports.is_image_attachment = is_image_attachment

local function attachment_ocr_scan(task)
  local attempted = 0
  local injected = 0
  local seen = {}

  if task.get_urls then
    for _, url in ipairs(task:get_urls() or {}) do
      seen[tostring(url)] = true
    end
  end

  for _, part in ipairs(task:get_parts() or {}) do
    if is_image_attachment(part) then
      attempted = attempted + 1
      local call_ok, text, ocr_error = pcall(exports.ocr_part, part)
      if not call_ok then
        warn(task, "%s: attachment %s OCR crashed: %s", SYMBOL, attempted, tostring(text))
      elseif text then
        for _, value in ipairs(exports.extract_urls(text)) do
          if not seen[value] then
            local parsed = rspamd_url.create(task:get_mempool(), value)
            if parsed then
              local normalized = tostring(parsed)
              if normalized ~= "" and not seen[normalized] then
                seen[value] = true
                seen[normalized] = true
                task:inject_url(parsed, part)
                injected = injected + 1
              end
            end
          end
        end
      elseif ocr_error then
        warn(task, "%s: attachment %s OCR failed: %s", SYMBOL, attempted, tostring(ocr_error))
      end
    end
  end

  if attempted > 0 then
    return true, 1.0, {
      "attachments=" .. attempted,
      "urls=" .. injected,
    }
  end
  return false
end

exports.callback = attachment_ocr_scan

rspamd_config:register_symbol({
  name = SYMBOL,
  -- URL extraction must run in the same prefilter phase as the dependent
  -- phishing rules. A normal-phase callback would inject URLs only after those
  -- rules had already completed.
  type = "prefilter",
  callback = attachment_ocr_scan,
  score = 0.0,
  group = "url",
  description = "OCR attempted for image attachments and recognized HTTP(S) URLs injected",
})

-- Existing phishing rules must consume URLs injected from attachment OCR.
rspamd_config:register_dependency("PHISH_URL_HEURISTIC", SYMBOL)
rspamd_config:register_dependency("LOOKALIKE_DOMAIN", SYMBOL)

return exports
