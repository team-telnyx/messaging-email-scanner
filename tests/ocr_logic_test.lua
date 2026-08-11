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

local settings = {
  min_size = 10240,
  max_size = 10485760,
  max_images = 1,
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

eq(ocr_select.is_overloaded({ connections = 32 }, 1.0, {
  max_connections = 32,
  max_load = 4.0,
}), true, "connection overload skips OCR")
eq(ocr_select.is_overloaded({ connections = 1 }, 4.0, {
  max_connections = 32,
  max_load = 4.0,
}), true, "load overload skips OCR")
eq(ocr_select.is_overloaded({ connections = 1 }, 1.0, {
  max_connections = 32,
  max_load = 4.0,
}), false, "healthy scanner runs OCR")

local matched, pattern = ocr_select.matches_spam("BUY V1AGRA NOW", {
  "[vw][i1]agra",
  "buy%s+now",
})
eq(matched, true, "OCR spam text matches")
eq(pattern, "[vw][i1]agra", "matched pattern is returned")
eq(ocr_select.matches_spam("Quarterly newsletter", { "[vw][i1]agra" }), false,
  "benign OCR text does not match")

print("ocr_logic_test: PASS")
