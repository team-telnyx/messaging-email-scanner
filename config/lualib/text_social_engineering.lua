-- MSG-1872: detect pure-text social engineering that has no URL or
-- traditional BEC transaction language. The rule deliberately requires every
-- signal below to keep generic external business mail from being penalized.

local SYMBOL = "TEXT_SOCIAL_ENGINEERING"

local authority_terms = {
  "vp",
  "cfo",
  "ceo",
  "director",
  "manager",
  "president",
}

local urgency_terms = {
  "urgent",
  "immediately",
  "as soon as possible",
  "by end of business",
  "today",
}

local action_terms = {
  "call me",
  "phone",
  "contact me",
  "reach me",
}

local function normalize_domain(domain)
  if not domain then
    return nil
  end

  domain = string.lower(tostring(domain)):gsub("^%s+", ""):gsub("%s+$", ""):gsub("%.$", "")
  if domain == "" then
    return nil
  end
  return domain
end

local function domain_from_address(address)
  if not address then
    return nil
  end
  return normalize_domain(tostring(address):match("@([%w%.%-]+)$"))
end

local function contains_term(text, term)
  local start = 1
  while true do
    local first, last = string.find(text, term, start, true)
    if not first then
      return false
    end

    local before = first == 1 and "" or string.sub(text, first - 1, first - 1)
    local after = last == #text and "" or string.sub(text, last + 1, last + 1)
    local before_ok = before == "" or not string.match(before, "[%a%d]")
    local after_ok = after == "" or not string.match(after, "[%a%d]")
    if before_ok and after_ok then
      return true
    end

    start = last + 1
  end
end

local function contains_any(text, terms)
  for _, term in ipairs(terms) do
    if contains_term(text, term) then
      return true
    end
  end
  return false
end

local function append_content(chunks, content)
  if content == nil then
    return
  end

  content = tostring(content)
  if content ~= "" then
    chunks[#chunks + 1] = content
  end
end

local function append_part_content(chunks, part)
  if part == nil then
    return
  end

  if part.get_content then
    append_content(chunks, part:get_content())
  else
    append_content(chunks, part)
  end
end

local function text_parts(task)
  if task.get_text_parts then
    return task:get_text_parts() or {}
  end
  if task.get_text_part then
    local part = task:get_text_part()
    return part and { part } or {}
  end
  return {}
end

local function is_text_only_without_urls(task, parts)
  if #parts == 0 then
    return false
  end

  -- get_text_parts() excludes attachments and multipart containers. Inspect the
  -- full MIME tree so a plain body plus an attachment is not called text-only.
  if task.get_parts then
    local mime_parts = task:get_parts() or {}
    if #mime_parts == 0 then
      return false
    end

    for _, part in ipairs(mime_parts) do
      local is_multipart = part.is_multipart and part:is_multipart()
      if not is_multipart then
        local major_type, subtype = part:get_type()
        major_type = string.lower(tostring(major_type or ""))
        subtype = string.lower(tostring(subtype or ""))
        if (part.is_message and part:is_message()) or
           (part.is_attachment and part:is_attachment()) or
           not (part.is_text and part:is_text()) or
           major_type ~= "text" or subtype ~= "plain" then
          return false
        end
      end
    end
  end

  for _, part in ipairs(parts) do
    if part.is_html and part:is_html() then
      return false
    end
  end

  if task.get_urls and next(task:get_urls() or {}) ~= nil then
    return false
  end
  -- Rspamd excludes telephone and email URLs from get_urls() by default. They
  -- still violate the no-URL prerequisite, so request those protocols too.
  if task.get_urls and next(task:get_urls({ "telephone", "mailto" }) or {}) ~= nil then
    return false
  end

  return true
end

local function from_identity(task)
  if task.get_from then
    local addresses = task:get_from("mime")
    local address = addresses and addresses[1]
    if address then
      return normalize_domain(address.domain) or domain_from_address(address.addr), address.name
    end
  end

  if task.get_header then
    local raw = task:get_header("From")
    if raw then
      return domain_from_address(tostring(raw):match("<([^>]+)>") or tostring(raw)), tostring(raw)
    end
  end

  return nil, nil
end

local function recipient_domains(task)
  local addresses = nil
  if task.get_recipients then
    addresses = task:get_recipients("smtp")
    if not addresses or #addresses == 0 then
      addresses = task:get_recipients("mime")
    end
  end

  local domains = {}
  for _, address in ipairs(addresses or {}) do
    local domain = normalize_domain(address.domain) or domain_from_address(address.addr)
    if domain then
      domains[#domains + 1] = domain
    end
  end

  if #domains == 0 and task.get_header then
    local raw = task:get_header("To")
    if raw then
      for domain in tostring(raw):gmatch("@([%w%.%-]+)") do
        domains[#domains + 1] = normalize_domain(domain)
      end
    end
  end

  return domains
end

local function is_external_sender(from_domain, domains)
  if not from_domain or #domains == 0 then
    return false
  end

  for _, domain in ipairs(domains) do
    if domain ~= from_domain then
      return true
    end
  end
  return false
end

local function has_phone_number(text)
  for candidate in text:gmatch("[%+%(]?%d[%d%s%(%)%.%-]+%d") do
    local _, digits = candidate:gsub("%d", "")
    if digits >= 10 and digits <= 15 then
      return true
    end
  end
  return false
end

local function message_text(task, parts, from_name)
  local chunks = {}
  append_content(chunks, from_name)
  append_content(chunks, task:get_subject())
  for _, part in ipairs(parts) do
    append_part_content(chunks, part)
  end

  -- Raw content is a fallback only for adapters with a text-part shell that has
  -- no decoded content. Rspamd normally supplies decoded text parts above.
  if #chunks == 0 and task.get_content then
    append_content(chunks, task:get_content())
  end

  -- Decoded text can wrap a phrase across lines or contain tabs. Collapse
  -- whitespace so indicator phrases retain their semantic boundaries.
  return string.lower(table.concat(chunks, "\n")):gsub("%s+", " ")
end

local function text_social_engineering_callback(task)
  local parts = text_parts(task)
  if not is_text_only_without_urls(task, parts) then
    return false
  end

  local from_domain, from_name = from_identity(task)
  if not is_external_sender(from_domain, recipient_domains(task)) then
    return false
  end

  local text = message_text(task, parts, from_name)
  if not contains_any(text, authority_terms) then
    return false
  end
  if not contains_any(text, urgency_terms) then
    return false
  end
  if not contains_any(text, action_terms) then
    return false
  end
  if not has_phone_number(text) then
    return false
  end

  return true
end

rspamd_config:register_symbol({
  name = SYMBOL,
  type = "normal",
  score = 4.0,
  description = "Text-only external authority impersonation with urgent phone callback request",
  callback = text_social_engineering_callback,
  group = "social_engineering",
})

return {
  callback = text_social_engineering_callback,
}
