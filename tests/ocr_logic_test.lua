local module_dir = assert(os.getenv("OCR_LUA_PATH"), "OCR_LUA_PATH is required")
package.path = module_dir .. "/?.lua;" .. package.path

local ocr_select = require "ocr_select"

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function part(mtype, subtype, size, multipart)
  return {
    get_type = function()
      return mtype, subtype
    end,
    get_length = function()
      return size
    end,
    is_multipart = function()
      return multipart or false
    end,
  }
end

-- Part with image metadata (simulates Rspamd rspamd_mimepart:get_image())
local function image_part(mtype, subtype, size, width, height)
  local p = part(mtype, subtype, size, false)
  p.get_image = function()
    return {
      get_width = function() return width end,
      get_height = function() return height end,
    }
  end
  return p
end

local settings = {
  min_size = 10240,
  max_size = 10485760,
  max_images = 1,
  max_pixels = 0,  -- disabled for basic selection tests (parts have no get_image)
  mime_types = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/bmp",
    "image/tiff",
  },
}

local selection = ocr_select.collect_parts({
  part("text", "plain", 200, false),
  part("image", "png", 20000, false),
  part("image", "jpeg", 30000, false),
  part("image", "gif", 40000, false),
  part("image", "tiff", 50000, false),
  part("image", "svg+xml", 60000, false),
  part("multipart", "mixed", 200000, true),
}, settings)

eq(#selection.eligible, 1, "max_images is enforced")
eq(selection.image_bytes, 200000, "all image bytes count toward ratio")
eq(selection.total_bytes, 200200, "multipart containers are excluded from ratio")

local small = ocr_select.collect_parts({
  part("text", "plain", 1000, false),
  part("image", "png", 10239, false),
}, settings)
eq(#small.eligible, 0, "images below min_size are skipped")

local too_large = ocr_select.collect_parts({
  part("image", "jpeg", 10485761, false),
}, settings)
eq(#too_large.eligible, 0, "images above max_size are skipped")

local selected, reason = ocr_select.should_ocr(0.81, 0.8)
eq(selected, true, "high image ratio selects OCR")
eq(reason, "image_ratio", "image-ratio selection reason")

selected, reason = ocr_select.should_ocr(0.8, 0.8)
eq(selected, false, "image-ratio threshold is strict")
eq(reason, "image_ratio_below_threshold", "below-threshold selection reason")

eq(ocr_select.is_overloaded(nil, 4.0, {
  max_load = 4.0,
}), true, "load overload skips OCR")
eq(ocr_select.is_overloaded(nil, 1.0, {
  max_load = 4.0,
}), false, "healthy scanner runs OCR")

-- Pixel limit tests: verify max_pixels guard uses get_image() API
local pixel_settings = {
  min_size = 10240,
  max_size = 10485760,
  max_images = 3,
  max_pixels = 1000000,
  mime_types = { "image/png" },
}

local within_pixels = image_part("image", "png", 50000, 500, 500)
local oversize_pixels = image_part("image", "png", 50000, 2000, 2000)
local no_image_meta = part("image", "png", 50000, false)
no_image_meta.get_image = function() return nil end

local pixel_sel = ocr_select.collect_parts({ within_pixels, oversize_pixels, no_image_meta }, pixel_settings)
eq(#pixel_sel.eligible, 2, "within-pixels and no-image-meta eligible; oversize skipped")

local only_oversize = ocr_select.collect_parts({ oversize_pixels }, pixel_settings)
eq(#only_oversize.eligible, 0, "oversize-pixel image is skipped")

local only_within = ocr_select.collect_parts({ within_pixels }, pixel_settings)
eq(#only_within.eligible, 1, "within-pixel image is eligible")

local matches, pattern = ocr_select.matches_spam("BUY V1AGRA NOW", {
  "[vw][i1]agra",
  "buy%s+now",
})
eq(matches, true, "OCR spam text matches")
eq(pattern, "[vw][i1]agra", "matched pattern is returned")
eq(ocr_select.matches_spam("Quarterly newsletter", { "[vw][i1]agra" }), false,
  "benign OCR text does not match")

print("ocr_logic_test: PASS")
