-- Pure selection helpers for the MSG-1797 OCR plugin.
-- Kept independent of Rspamd globals so the latency and eligibility policy can
-- be unit tested with the system Lua interpreter.

local exports = {}

local function mime_set(values)
  local result = {}
  for _, value in ipairs(values or {}) do
    result[string.lower(value)] = true
  end
  return result
end

function exports.collect_parts(parts, settings)
  local allowed = mime_set(settings.mime_types)
  local eligible = {}
  local total_bytes = 0
  local image_bytes = 0

  for _, part in ipairs(parts or {}) do
    local is_multipart = part.is_multipart and part:is_multipart() or false
    if not is_multipart then
      local length = tonumber(part:get_length()) or 0
      local mtype, subtype = part:get_type()
      mtype = mtype and string.lower(mtype) or ""
      subtype = subtype and string.lower(subtype) or ""
      total_bytes = total_bytes + length

      if mtype == "image" then
        image_bytes = image_bytes + length
        local mime = mtype .. "/" .. subtype
        if allowed[mime]
            and length >= settings.min_size
            and length <= settings.max_size
            and #eligible < settings.max_images then
          -- Check pixel dimensions if max_pixels is set
          local max_px = tonumber(settings.max_pixels) or 0
          if max_px > 0 then
            local w = tonumber(part:get_width()) or 0
            local h = tonumber(part:get_height()) or 0
            if w * h > max_px then
              goto continue
            end
          end
          eligible[#eligible + 1] = part
        end
        ::continue::
      end
    end
  end

  return {
    eligible = eligible,
    total_bytes = total_bytes,
    image_bytes = image_bytes,
    image_ratio = total_bytes > 0 and image_bytes / total_bytes or 0,
  }
end

function exports.should_ocr(image_ratio, image_ratio_threshold)
  if (tonumber(image_ratio) or 0) > image_ratio_threshold then
    return true, "image_ratio"
  end
  return false, "image_ratio_below_threshold"
end

function exports.is_overloaded(worker_stats, load_average, settings)
  -- Use load average (system metric), not cumulative connection counter
  local load = tonumber(load_average) or 0
  local max_load = tonumber(settings.max_load) or 0
  if max_load > 0 and load >= max_load then
    return true, "load"
  end

  return false
end

function exports.matches_spam(text, patterns)
  local lower = string.lower(text or "")
  for _, pattern in ipairs(patterns or {}) do
    if lower:find(pattern) then
      return true, pattern
    end
  end
  return false
end

return exports
