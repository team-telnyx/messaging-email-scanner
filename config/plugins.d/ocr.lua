-- MSG-1797: selective Tesseract OCR prefilter for Rspamd 3.10.
--
-- Rspamd 3.10 does not ship an OCR module. This plugin extracts eligible image
-- MIME parts, invokes Tesseract under a hard timeout, injects recognized text
-- into the in-memory scan task for content rules/Bayes, and emits observability
-- symbols. io.popen is intentionally synchronous: selection, overload gates,
-- max_images and timeout bounds keep that cost off the normal mail path.

local lua_mime = require "lua_mime"
local lua_util = require "lua_util"
local ocr_select = require "ocr_select"
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"

local N = "ocr"
local defaults = {
  enabled = false,
  tesseract_bin = "/usr/bin/tesseract",
  timeout_bin = "/usr/bin/timeout",
  language = "eng",
  min_size = 10240,
  max_size = 10485760,
  mime_types = { "image/png", "image/jpeg", "image/gif", "image/bmp", "image/tiff" },
  max_images = 1,
  timeout = 2,
  max_output_chars = 8192,
  image_ratio_threshold = 0.80,
  max_connections = 32,
  max_load = 4.0,
  feed_bayes = true,
  spam_score = 5.0,
  spam_patterns = {
    "[vw][i1]agra",
    "buy%s+now",
    "free%s+money",
    "limited%s+time%s+offer",
    "claim%s+your%s+prize",
    "crypto%s+investment",
  },
}

local opts = rspamd_config:get_all_opt(N)
if not opts then
  rspamd_logger.infox(rspamd_config, "%s: no configuration; module disabled", N)
  return
end

local settings = {}
for key, value in pairs(defaults) do
  settings[key] = value
end
for key, value in pairs(opts) do
  settings[key] = value
end
if not settings.enabled then
  rspamd_logger.infox(rspamd_config, "%s: module disabled by configuration", N)
  return
end

local function shell_quote(value)
  return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function read_load_average()
  local handle = io.open("/proc/loadavg", "r")
  if not handle then
    return 0
  end
  local line = handle:read("*l") or ""
  handle:close()
  return tonumber(line:match("^([0-9.]+)")) or 0
end

local function clean_ocr_text(text)
  text = (text or ""):gsub("%z", " ")
  text = text:gsub("\r\n", "\n"):gsub("\r", "\n")
  text = text:gsub("[ \t]+", " "):gsub("\n+", "\n")
  text = text:match("^%s*(.-)%s*$") or ""
  return text:sub(1, settings.max_output_chars)
end

local function run_tesseract(part)
  local input_path = "/tmp/rspamd-ocr-" .. rspamd_util.random_hex(16) .. ".img"
  local output, open_error
  local handle

  handle, open_error = io.open(input_path, "wb")
  if not handle then
    return nil, "temporary file: " .. tostring(open_error)
  end

  local content = part:get_content()
  local wrote, write_error = handle:write(tostring(content or ""))
  handle:close()
  if not wrote then
    rspamd_util.unlink(input_path)
    return nil, "temporary file write: " .. tostring(write_error)
  end

  local command = string.format(
    "%s --signal=KILL %d %s %s stdout -l %s --psm 6 2>/dev/null",
    shell_quote(settings.timeout_bin),
    math.max(1, math.floor(tonumber(settings.timeout) or 2)),
    shell_quote(settings.tesseract_bin),
    shell_quote(input_path),
    shell_quote(settings.language)
  )

  local pipe, pipe_error = io.popen(command, "r")
  if not pipe then
    rspamd_util.unlink(input_path)
    return nil, "tesseract start: " .. tostring(pipe_error)
  end

  output = pipe:read("*a") or ""
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

local function newline(task)
  local kind = task:get_newlines_type()
  if kind == "cr" then
    return "\r"
  elseif kind == "lf" then
    return "\n"
  end
  return "\r\n"
end

local function append_piece(out, piece, nl)
  if type(piece) == "string" then
    out[#out + 1] = piece
    out[#out + 1] = nl
  elseif type(piece) == "table" then
    out[#out + 1] = piece[1]
    if piece[2] then
      out[#out + 1] = nl
    end
  else
    out[#out + 1] = piece
    out[#out + 1] = nl
  end
end

local function append_to_text_parts(task, text)
  local escaped = text:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
  local text_footer = "\n\n[OCR extracted text]\n" .. text .. "\n"
  local html_footer = "<div data-rspamd-ocr=\"true\">[OCR extracted text] " .. escaped .. "</div>"
  local rewrite = lua_mime.add_text_footer(task, html_footer, text_footer)
  if not rewrite or not rewrite.out then
    return false
  end

  local nl = newline(task)
  local out = {}
  local seen_cte = false

  task:headers_foreach(function(name, header)
    local lower_name = string.lower(name)
    if rewrite.need_rewrite_ct and lower_name == "content-type" then
      out[#out + 1] = string.format("Content-Type: %s/%s; charset=utf-8%s",
        rewrite.new_ct.type, rewrite.new_ct.subtype, nl)
    elseif rewrite.need_rewrite_ct and lower_name == "content-transfer-encoding" then
      out[#out + 1] = string.format("Content-Transfer-Encoding: %s%s",
        rewrite.new_cte or "quoted-printable", nl)
      seen_cte = true
    else
      out[#out + 1] = (header.raw:gsub("\r?\n$", "")) .. nl
    end
  end, { full = true })

  if rewrite.need_rewrite_ct and not seen_cte then
    out[#out + 1] = "Content-Transfer-Encoding: " ..
      (rewrite.new_cte or "quoted-printable") .. nl
  end
  out[#out + 1] = nl
  for _, piece in ipairs(rewrite.out) do
    append_piece(out, piece, nl)
  end

  return task:set_message(out)
end

local function append_to_subject(task, text)
  local nl = newline(task)
  local out = {}
  local replaced = false
  local one_line = text:gsub("%s+", " "):sub(1, 2048)

  task:headers_foreach(function(name, header)
    if string.lower(name) == "subject" and not replaced then
      out[#out + 1] = "Subject: " .. (header.decoded or "") .. " [OCR] " .. one_line .. nl
      replaced = true
    else
      out[#out + 1] = (header.raw:gsub("\r?\n$", "")) .. nl
    end
  end, { full = true })
  if not replaced then
    out[#out + 1] = "Subject: [OCR] " .. one_line .. nl
  end
  out[#out + 1] = nl
  out[#out + 1] = task:get_rawbody()

  return task:set_message(out)
end

local function feed_ocr_text(task, text)
  local ok = append_to_text_parts(task, text)
  if not ok then
    ok = append_to_subject(task, text)
  end
  return ok
end

local function worker_stats(task)
  local worker = task:get_worker()
  if not worker then
    return {}
  end
  local ok, stats = pcall(function()
    return worker:get_stat()
  end)
  return ok and stats or {}
end

local function ocr_callback(task)
  local overloaded, overload_reason = ocr_select.is_overloaded(
    worker_stats(task), read_load_average(), settings)
  if overloaded then
    task:insert_result("OCR_SKIPPED", 1.0, "overloaded:" .. overload_reason)
    return
  end

  local selection = ocr_select.collect_parts(task:get_parts() or {}, settings)
  if #selection.eligible == 0 then
    task:insert_result("OCR_SKIPPED", 1.0, "no_eligible_images")
    return
  end

  local selected, selection_reason = ocr_select.should_ocr(
    selection.image_ratio, settings.image_ratio_threshold)
  if not selected then
    task:insert_result("OCR_SKIPPED", 1.0, selection_reason)
    return
  end

  local extracted = {}
  local attempted = 0
  for _, part in ipairs(selection.eligible) do
    attempted = attempted + 1
    local text, err = run_tesseract(part)
    if text and #text > 0 then
      extracted[#extracted + 1] = text
    elseif err then
      rspamd_logger.warnx(task, "%s: image %s failed: %s", N, attempted, err)
    end
  end

  if #extracted == 0 then
    task:insert_result("OCR_SKIPPED", 1.0, "no_text", "attempted=" .. attempted)
    return
  end

  local text = table.concat(extracted, "\n")
  if settings.feed_bayes and not feed_ocr_text(task, text) then
    rspamd_logger.warnx(task, "%s: could not inject extracted text into scan task", N)
  end

  task:insert_result("OCR_PROCESSED", 1.0,
    "reason=" .. selection_reason,
    "images=" .. attempted,
    "ratio=" .. string.format("%.3f", selection.image_ratio))

  local spam, pattern = ocr_select.matches_spam(text, settings.spam_patterns)
  if spam then
    local preview = text:gsub("%s+", " "):sub(1, 160)
    task:insert_result("OCR_SPAM_TEXT", 1.0, "pattern=" .. pattern, preview)
  end
end

local parent_id = rspamd_config:register_symbol({
  name = "OCR_CHECK",
  type = "prefilter",
  callback = ocr_callback,
  priority = lua_util.symbols_priorities.low,
  flags = "empty,explicit_disable,ignore_passthrough,nostat",
  group = N,
  augmentations = {
    string.format("timeout=%d", settings.timeout * settings.max_images),
  },
})

rspamd_config:register_symbol({
  name = "OCR_PROCESSED",
  type = "virtual",
  parent = parent_id,
  score = 0.0,
  group = N,
})
rspamd_config:register_symbol({
  name = "OCR_SKIPPED",
  type = "virtual",
  parent = parent_id,
  score = 0.0,
  group = N,
})
rspamd_config:register_symbol({
  name = "OCR_SPAM_TEXT",
  type = "virtual",
  parent = parent_id,
  score = settings.spam_score,
  group = N,
})
