-- MSG-1847: detect ASCII homoglyph/lookalike domains in URLs and sender headers.

local exports = {}

local SYMBOL = "LOOKALIKE_DOMAIN"

-- Keep this list in sync with phish_url_heuristics.lua.
local brands = {
  "paypal",
  "apple",
  "google",
  "microsoft",
  "amazon",
  "netflix",
  "facebook",
  "instagram",
  "linkedin",
  "twitter",
  "bankofamerica",
  "chase",
  "wellsfargo",
  "citibank",
  "americanexpress",
  "docusign",
  "dropbox",
  "adobe",
  "zoom",
  "ebay",
  "office365",
  "docusign",
  "zoom",
  "slack",
}

local confusables = {
  { source = "rn", replacements = { "m" } },
  { source = "vv", replacements = { "w" } },
  { source = "0", replacements = { "o" } },
  { source = "1", replacements = { "l", "i" } },
  { source = "3", replacements = { "e" } },
  { source = "5", replacements = { "s" } },
  { source = "@", replacements = { "a" } },
  { source = "$", replacements = { "s" } },
  { source = "8", replacements = { "b" } },
  { source = "7", replacements = { "t" } },
}

-- Common non-ASCII characters that are visually confusable with Latin letters.
-- Keys are Unicode codepoints so this works without relying on Rspamd's optional
-- IDN or Lua utf8 modules. Values are lower-case because hosts are case-insensitive.
local unicode_confusables = {
  -- Cyrillic upper case
  [0x0410] = "a", [0x0412] = "b", [0x0421] = "c", [0x0415] = "e",
  [0x041D] = "h", [0x0406] = "i", [0x0408] = "j", [0x041A] = "k",
  [0x041C] = "m", [0x041E] = "o", [0x0420] = "p", [0x0405] = "s",
  [0x0422] = "t", [0x0425] = "x", [0x04AE] = "y", [0x04C0] = "l",
  -- Cyrillic lower case
  [0x0430] = "a", [0x0432] = "b", [0x0441] = "c", [0x0435] = "e",
  [0x04BB] = "h", [0x0456] = "i", [0x0458] = "j", [0x043A] = "k",
  [0x043C] = "m", [0x043E] = "o", [0x0440] = "p", [0x0455] = "s",
  [0x0442] = "t", [0x0445] = "x", [0x0443] = "y", [0x04CF] = "l",
  [0x050D] = "g", -- Cyrillic small Komi sje
  [0x0261] = "g", -- Latin small script g
  -- Greek upper and lower case
  [0x0391] = "a", [0x0392] = "b", [0x0395] = "e", [0x0396] = "z",
  [0x0397] = "h", [0x0399] = "i", [0x039A] = "k", [0x039C] = "m",
  [0x039D] = "n", [0x039F] = "o", [0x03A1] = "p", [0x03A4] = "t",
  [0x03A5] = "y", [0x03A7] = "x",
  [0x03B1] = "a", [0x03B2] = "b", [0x03B5] = "e", [0x03B6] = "z",
  [0x03B7] = "h", [0x03B9] = "i", [0x03BA] = "k", [0x03BC] = "m",
  [0x03BD] = "n", [0x03BF] = "o", [0x03C1] = "p", [0x03C4] = "t",
  [0x03C5] = "y", [0x03C7] = "x",
}

local common_multi_label_suffixes = {
  ["co.uk"] = true,
  ["co.jp"] = true,
  ["co.kr"] = true,
  ["co.nz"] = true,
  ["co.in"] = true,
  ["co.za"] = true,
  ["com.au"] = true,
  ["com.br"] = true,
  ["com.mx"] = true,
  ["com.cn"] = true,
  ["com.hk"] = true,
  ["com.tw"] = true,
  ["com.sg"] = true,
  ["com.my"] = true,
  ["com.ph"] = true,
}

local function normalize_host(host)
  host = string.lower(tostring(host or ""))
  host = host:gsub("^%s+", ""):gsub("%s+$", "")
  host = host:gsub("^%.*", ""):gsub("%.+$", "")
  return (host:gsub(":%d+$", ""))
end

local function split_labels(host)
  local labels = {}
  for label in normalize_host(host):gmatch("[^.]+") do
    labels[#labels + 1] = label
  end
  return labels
end

local function punycode_digit(byte)
  if byte >= string.byte("a") and byte <= string.byte("z") then
    return byte - string.byte("a")
  end
  if byte >= string.byte("A") and byte <= string.byte("Z") then
    return byte - string.byte("A")
  end
  if byte >= string.byte("0") and byte <= string.byte("9") then
    return byte - string.byte("0") + 26
  end
  return nil
end

local function adapt_punycode_bias(delta, points, first_time)
  delta = math.floor(delta / (first_time and 700 or 2))
  delta = delta + math.floor(delta / points)

  local adjustment = 0
  while delta > 455 do
    delta = math.floor(delta / 35)
    adjustment = adjustment + 36
  end

  return adjustment + math.floor((36 * delta) / (delta + 38))
end

local function codepoint_to_utf8(codepoint)
  if codepoint <= 0x7f then
    return string.char(codepoint)
  elseif codepoint <= 0x7ff then
    return string.char(
      0xc0 + math.floor(codepoint / 0x40),
      0x80 + (codepoint % 0x40)
    )
  elseif codepoint <= 0xffff then
    return string.char(
      0xe0 + math.floor(codepoint / 0x1000),
      0x80 + (math.floor(codepoint / 0x40) % 0x40),
      0x80 + (codepoint % 0x40)
    )
  end
  return string.char(
    0xf0 + math.floor(codepoint / 0x40000),
    0x80 + (math.floor(codepoint / 0x1000) % 0x40),
    0x80 + (math.floor(codepoint / 0x40) % 0x40),
    0x80 + (codepoint % 0x40)
  )
end

-- Decode one RFC 3492 Punycode payload (without the xn-- prefix). The returned
-- codepoint list is used by mixed-script and confusable checks, avoiding a
-- runtime dependency on an IDN library that is not present in every Rspamd build.
function exports.decode_punycode(input)
  input = tostring(input or "")
  if input == "" then
    return nil, "empty punycode payload"
  end
  -- A DNS label is limited to 63 octets including the four-byte xn-- prefix.
  -- Bound the decoder before allocating output or entering RFC 3492 loops.
  if #input > 59 then
    return nil, "punycode payload exceeds DNS label limit"
  end

  local output = {}
  local delimiter
  for index = 1, #input do
    if input:byte(index) == string.byte("-") then
      delimiter = index
    end
  end

  local input_index = 1
  if delimiter then
    for index = 1, delimiter - 1 do
      local byte = input:byte(index)
      if not byte or byte >= 0x80 then
        return nil, "non-ASCII basic code point"
      end
      output[#output + 1] = byte
    end
    input_index = delimiter + 1
  end

  local codepoint = 128
  local accumulator = 0
  local bias = 72
  while input_index <= #input do
    local previous_accumulator = accumulator
    local weight = 1
    local step = 36

    while true do
      if input_index > #input then
        return nil, "truncated punycode sequence"
      end
      local digit = punycode_digit(input:byte(input_index))
      input_index = input_index + 1
      if digit == nil then
        return nil, "invalid punycode digit"
      end

      local max_delta = 0x10ffff * (#output + 2)
      if weight > max_delta or digit > math.floor((max_delta - accumulator) / weight) then
        return nil, "punycode integer overflow"
      end
      accumulator = accumulator + digit * weight
      local threshold
      if step <= bias + 1 then
        threshold = 1
      elseif step >= bias + 26 then
        threshold = 26
      else
        threshold = step - bias
      end
      if digit < threshold then
        break
      end

      local multiplier = 36 - threshold
      if weight > math.floor(max_delta / multiplier) then
        return nil, "punycode integer overflow"
      end
      weight = weight * multiplier
      step = step + 36
    end

    local point_count = #output + 1
    bias = adapt_punycode_bias(
      accumulator - previous_accumulator,
      point_count,
      previous_accumulator == 0
    )
    codepoint = codepoint + math.floor(accumulator / point_count)
    accumulator = accumulator % point_count
    if codepoint > 0x10ffff or (codepoint >= 0xd800 and codepoint <= 0xdfff) then
      return nil, "invalid Unicode code point"
    end

    table.insert(output, accumulator + 1, codepoint)
    accumulator = accumulator + 1
  end

  local decoded = {}
  for _, point in ipairs(output) do
    decoded[#decoded + 1] = codepoint_to_utf8(point)
  end
  return table.concat(decoded), nil, output
end

local function unicode_script(codepoint)
  if (codepoint >= 0x41 and codepoint <= 0x5a) or
     (codepoint >= 0x61 and codepoint <= 0x7a) or
     (codepoint >= 0xc0 and codepoint <= 0x24f) or
     (codepoint >= 0x250 and codepoint <= 0x2af) or
     (codepoint >= 0x1e00 and codepoint <= 0x1eff) then
    return "latin"
  end
  if (codepoint >= 0x370 and codepoint <= 0x3ff) or
     (codepoint >= 0x1f00 and codepoint <= 0x1fff) then
    return "greek"
  end
  if (codepoint >= 0x400 and codepoint <= 0x52f) or
     (codepoint >= 0x1c80 and codepoint <= 0x1c8f) or
     (codepoint >= 0x2de0 and codepoint <= 0x2dff) or
     (codepoint >= 0xa640 and codepoint <= 0xa69f) then
    return "cyrillic"
  end
  return nil
end

local function confusable_skeleton(codepoints)
  local skeleton = {}
  for _, codepoint in ipairs(codepoints) do
    local replacement = unicode_confusables[codepoint]
    if replacement then
      skeleton[#skeleton + 1] = replacement
    elseif codepoint >= string.byte("A") and codepoint <= string.byte("Z") then
      skeleton[#skeleton + 1] = string.char(codepoint + 32)
    elseif codepoint < 0x80 then
      skeleton[#skeleton + 1] = string.char(codepoint)
    else
      -- Preserve unmapped Unicode so it cannot disappear and create a false
      -- protected-brand match.
      skeleton[#skeleton + 1] = codepoint_to_utf8(codepoint)
    end
  end
  return table.concat(skeleton)
end

function exports.detect_idn_homograph(host)
  host = normalize_host(host)
  local labels = split_labels(host)
  local decoded_labels = {}
  local scripts = {}
  local candidates = {}
  local has_punycode = false

  for _, label in ipairs(labels) do
    if label:sub(1, 4) == "xn--" then
      has_punycode = true
      local decoded, decode_error, codepoints = exports.decode_punycode(label:sub(5))
      if not decoded then
        return nil, nil, nil, decode_error
      end
      decoded_labels[#decoded_labels + 1] = decoded
      candidates[#candidates + 1] = {
        encoded = label,
        skeleton = confusable_skeleton(codepoints),
      }
      for _, point in ipairs(codepoints) do
        local script = unicode_script(point)
        if script then scripts[script] = true end
      end
    else
      decoded_labels[#decoded_labels + 1] = label
      for index = 1, #label do
        local script = unicode_script(label:byte(index))
        if script then scripts[script] = true end
      end
    end
  end

  if not has_punycode then
    return nil
  end

  if not scripts.latin or not (scripts.cyrillic or scripts.greek) then
    return nil
  end

  for _, candidate in ipairs(candidates) do
    local components = { candidate.skeleton }
    if candidate.skeleton:find("[-_]") then
      for component in candidate.skeleton:gmatch("[^-_]+") do
        components[#components + 1] = component
      end
    end
    for _, component in ipairs(components) do
      for _, brand in ipairs(brands) do
        if component == brand then
          return brand, candidate.encoded, table.concat(decoded_labels, ".")
        end
      end
    end
  end
  return nil
end

local function suffix_matches(host_labels, registered_labels)
  if #registered_labels == 0 or #registered_labels > #host_labels then
    return false
  end

  local offset = #host_labels - #registered_labels
  for index, label in ipairs(registered_labels) do
    if host_labels[offset + index] ~= label then
      return false
    end
  end
  return true
end

-- Return the SLD and all subdomain labels while excluding the public suffix.
local function domain_labels(host, registered_domain)
  local host_labels = split_labels(host)
  if #host_labels == 0 then
    return {}
  end

  local registered_labels = split_labels(registered_domain)
  if suffix_matches(host_labels, registered_labels) then
    local result = {}
    local subdomain_count = #host_labels - #registered_labels
    for index = 1, subdomain_count do
      result[#result + 1] = host_labels[index]
    end
    -- Rspamd's get_tld() returns the registered domain. Its first label is the SLD.
    result[#result + 1] = registered_labels[1]
    return result
  end

  local suffix_count = 1
  if #host_labels >= 2 then
    local suffix = host_labels[#host_labels - 1] .. "." .. host_labels[#host_labels]
    if common_multi_label_suffixes[suffix] then
      suffix_count = 2
    end
  end

  local result = {}
  local last_domain_label = math.max(1, #host_labels - suffix_count)
  for index = 1, last_domain_label do
    result[#result + 1] = host_labels[index]
  end
  return result
end

-- Compare a domain-label component to a brand without materializing an
-- exponential number of variants. The recursion explores the unchanged input
-- and each valid confusable replacement, and only succeeds if at least one
-- replacement was required.
local function component_matches_brand(component, brand)
  local memo = {}

  local function matches(source_index, brand_index, changed)
    local key = source_index .. ":" .. brand_index .. ":" .. tostring(changed)
    if memo[key] ~= nil then
      return memo[key]
    end

    if source_index > #component or brand_index > #brand then
      local result = source_index > #component and brand_index > #brand and changed
      memo[key] = result
      return result
    end

    if component:sub(source_index, source_index) == brand:sub(brand_index, brand_index) and
       matches(source_index + 1, brand_index + 1, changed) then
      memo[key] = true
      return true
    end

    for _, mapping in ipairs(confusables) do
      local source_end = source_index + #mapping.source - 1
      if component:sub(source_index, source_end) == mapping.source then
        for _, replacement in ipairs(mapping.replacements) do
          local replacement_end = brand_index + #replacement - 1
          if brand:sub(brand_index, replacement_end) == replacement and
             matches(source_end + 1, replacement_end + 1, true) then
            memo[key] = true
            return true
          end
        end
      end
    end

    memo[key] = false
    return false
  end

  return matches(1, 1, false)
end

local function label_components(label)
  local components = { label }
  if label:find("[-_]") then
    for component in label:gmatch("[^-_]+") do
      components[#components + 1] = component
    end
  end
  return components
end

function exports.check_domain(host, registered_domain)
  host = normalize_host(host)
  if host == "" then
    return nil
  end

  for _, label in ipairs(domain_labels(host, registered_domain)) do
    for _, component in ipairs(label_components(label)) do
      for _, brand in ipairs(brands) do
        if component_matches_brand(component, brand) then
          return brand, component
        end
      end
    end
  end

  return nil
end

local function address_domain(address)
  if address == nil then
    return nil
  end

  if type(address) == "table" and address.domain then
    local domain = normalize_host(address.domain)
    return domain ~= "" and domain or nil
  end

  if type(address) == "table" and address.addr then
    address = address.addr
  end

  local value = string.lower(tostring(address))
  local domain = value:match("@([^@<>%s,;]+)%s*>?%s*$")
  domain = normalize_host(domain)
  return domain ~= "" and domain or nil
end

local function header_domain(task, header_name)
  if not task.get_header then
    return nil
  end
  return address_domain(task:get_header(header_name))
end

local function from_domain(task)
  if task.get_from then
    local from_addresses = task:get_from("mime")
    if from_addresses and from_addresses[1] then
      local domain = address_domain(from_addresses[1])
      if domain then
        return domain
      end
    end
  end
  return header_domain(task, "From")
end

local function reply_to_domain(task)
  if task.get_reply_sender then
    local domain = address_domain(task:get_reply_sender())
    if domain then
      return domain
    end
  end
  return header_domain(task, "Reply-To")
end

local function levenshtein(left, right)
  local previous = {}
  for column = 0, #right do
    previous[column] = column
  end

  for row = 1, #left do
    local current = { [0] = row }
    local left_char = left:sub(row, row)
    for column = 1, #right do
      local cost = left_char == right:sub(column, column) and 0 or 1
      current[column] = math.min(
        current[column - 1] + 1,
        previous[column] + 1,
        previous[column - 1] + cost
      )
    end
    previous = current
  end

  return previous[#right]
end

local function public_suffix(domain)
  local labels = split_labels(domain)
  if #labels < 2 then
    return labels[#labels] or ""
  end

  local suffix = labels[#labels - 1] .. "." .. labels[#labels]
  if common_multi_label_suffixes[suffix] then
    return suffix
  end
  return labels[#labels]
end

-- Extract the registered domain from a hostname (e.g. mail1.company.com → company.com)
local function registered_domain_from_host(host)
  local labels = split_labels(host)
  if #labels < 2 then
    return host
  end
  local suffix = labels[#labels - 1] .. "." .. labels[#labels]
  if #labels >= 3 and common_multi_label_suffixes[suffix] then
    return labels[#labels - 2] .. "." .. suffix
  end
  return suffix
end

exports.levenshtein = levenshtein
exports.brands = brands

local function lookalike_domain(task)
  for _, url in ipairs(task:get_urls() or {}) do
    local host = normalize_host(url:get_host())
    local registered_domain = url:get_tld()
    local idn_brand, idn_label, decoded_host = exports.detect_idn_homograph(host)
    if idn_brand then
      return true, 1.0, {
        "idn_homograph",
        "source=url",
        "host=" .. host,
        "label=" .. idn_label,
        "brand=" .. idn_brand,
        "decoded=" .. decoded_host,
      }
    end
    local brand, component = exports.check_domain(host, registered_domain)
    if brand then
      return true, 1.0, {
        "homoglyph",
        "source=url",
        "host=" .. host,
        "label=" .. component,
        "brand=" .. brand,
      }
    end
    -- Levenshtein check: only compare the SLD (registered domain's first label)
    -- against the brand list. Skip subdomain labels to avoid false positives
    -- (e.g. "apps" is distance 2 from "apple" but is a legitimate subdomain).
    local reg_labels = split_labels(registered_domain or "")
    if reg_labels and reg_labels[1] then
      local sld = reg_labels[1]
      for _, component in ipairs(label_components(sld)) do
        -- Skip if the SLD IS the exact brand (legitimate brand domain)
        local is_exact_brand = false
        for _, b in ipairs(brands) do
          if component == b then is_exact_brand = true; break end
        end
        if not is_exact_brand then
          for _, brand in ipairs(brands) do
            local distance = levenshtein(component, brand)
            if distance >= 1 and distance <= 2 then
              return true, 1.0, {
                "levenshtein",
                "source=url",
                "host=" .. host,
                "label=" .. component,
                "brand=" .. brand,
                "distance=" .. distance,
              }
            end
          end
        end
      end
    end
  end

  local mime_from_domain = from_domain(task)
  if mime_from_domain then
    local idn_brand, idn_label, decoded_host = exports.detect_idn_homograph(mime_from_domain)
    if idn_brand then
      return true, 1.0, {
        "idn_homograph",
        "source=from",
        "host=" .. mime_from_domain,
        "label=" .. idn_label,
        "brand=" .. idn_brand,
        "decoded=" .. decoded_host,
      }
    end
    local brand, component = exports.check_domain(mime_from_domain)
    if brand then
      return true, 1.0, {
        "homoglyph",
        "source=from",
        "host=" .. mime_from_domain,
        "label=" .. component,
        "brand=" .. brand,
      }
    end
    -- Levenshtein check: only compare the SLD against the brand list
    local from_reg = registered_domain_from_host(mime_from_domain)
    local reg_labels = split_labels(from_reg or "")
    if reg_labels and reg_labels[1] then
      local sld = reg_labels[1]
      for _, component in ipairs(label_components(sld)) do
        local is_exact_brand = false
        for _, b in ipairs(brands) do
          if component == b then is_exact_brand = true; break end
        end
        if not is_exact_brand then
          for _, brand in ipairs(brands) do
            local distance = levenshtein(component, brand)
            if distance >= 1 and distance <= 2 then
              return true, 1.0, {
                "levenshtein",
                "source=from",
                "host=" .. mime_from_domain,
                "label=" .. component,
                "brand=" .. brand,
                "distance=" .. distance,
              }
            end
          end
        end
      end
    end
  end

  local mime_reply_to_domain = reply_to_domain(task)
  if mime_from_domain and mime_reply_to_domain and mime_from_domain ~= mime_reply_to_domain then
    -- Compare registered domains to avoid false positives on sibling subdomains.
    -- Use Rspamd's get_tld() when available (URL-based), fall back to our resolver.
    local from_reg = registered_domain_from_host(mime_from_domain)
    local reply_reg = registered_domain_from_host(mime_reply_to_domain)
    if from_reg and reply_reg and from_reg ~= reply_reg then
      if public_suffix(mime_from_domain) == public_suffix(mime_reply_to_domain) then
        local distance = levenshtein(from_reg, reply_reg)
        if distance >= 1 and distance <= 2 then
          return true, 1.0, {
            "reply_to_distance",
            "distance=" .. distance,
            "from=" .. from_reg,
            "reply_to=" .. reply_reg,
          }
        end
      end
    end
  end

  return false
end

exports.callback = lookalike_domain

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "prefilter",
  callback = lookalike_domain,
  score = 6.0,
  group = "url",
  description = "URL or sender domain is a homoglyph/lookalike",
})

return exports
