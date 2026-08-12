-- MSG-1831: detect Business Email Compromise language without relying on URLs.
-- Each heuristic requires terms from two groups so isolated business language
-- does not emit BEC_PATTERN.

local gift_card_terms = {
  "gift card",
  "itunes card",
  "steam card",
  "google play card",
  "amazon card",
  "apple card",
}

-- Terms use word-boundary matching via contains_word() — no trailing-space hacks needed.
local purchase_terms = {
  "purchase",
  "buy",
  "need you to",
  "pickup",
  "grab",
}

local wire_terms = {
  "wire transfer",
  "swift",
  "banking details",
  "routing number",
  "account number",
}

local urgency_terms = {
  "today",
  "urgent",
  "immediately",
  "before cutoff",
  "time-sensitive",
  "asap",
}

local confidentiality_terms = {
  "handle discreetly",
  "don't call",
  "between us",
  "i'm in a meeting",
  "can't talk",
  "text me only",
}

local transaction_terms = {
  "payment",
  "transfer",
  "purchase",
  "wire transfer",
  "fund",
  "funds",
}

-- Word-boundary matching: check that the term is not part of a larger word.
-- "fund" won't match "refund", "buy" won't match "buyer", but "buy:" and "buy " both match.
-- Allows trailing "s" for plural forms (e.g. "gift card" matches "gift cards").
local function contains_word(text, term)
  local start = 1
  while true do
    local s, e = string.find(text, term, start, true)
    if not s then
      return false
    end
    -- Check character before: must be non-letter (or start of text)
    local before_ok = (s == 1) or not string.match(string.sub(text, s - 1, s - 1), "%a")
    -- Check character after: must be non-letter, non-digit (or end of text)
    -- Allow trailing "s" for plurals (gift cards, funds), but the character
    -- after "s" must also be non-letter, non-digit (prevents "funds2" matching "fund").
    local after_char = ""
    if e < #text then
      after_char = string.sub(text, e + 1, e + 1)
    end
    local after_ok = (e == #text) or
      not string.match(after_char, "[%a%d]") or
      (after_char == "s" and (e + 1 == #text or not string.match(string.sub(text, e + 2, e + 2), "[%a%d]")))
    if before_ok and after_ok then
      return true
    end
    start = e + 1
  end
end

local function contains_any(text, terms)
  for _, term in ipairs(terms) do
    if contains_word(text, term) then
      return true
    end
  end
  return false
end

local function append_content(chunks, content)
  if content == nil then
    return
  end

  local text = tostring(content)
  if text ~= "" then
    chunks[#chunks + 1] = text
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

local function task_text(task)
  local chunks = {}
  append_content(chunks, task:get_subject())
  local subject_chunks = #chunks

  -- Rspamd exposes all decoded text parts through get_text_parts(). Keep the
  -- singular fallback for task adapters that expose a single decoded part.
  if task.get_text_parts then
    for _, part in ipairs(task:get_text_parts() or {}) do
      append_part_content(chunks, part)
    end
  elseif task.get_text_part then
    append_part_content(chunks, task:get_text_part())
  end

  -- Raw task content is a last resort for non-MIME input with no text part.
  if #chunks == subject_chunks and task.get_content then
    append_content(chunks, task:get_content())
  end

  return string.lower(table.concat(chunks, "\n"))
end

-- Extract domain from email address in a header value.
-- Handles "Name <user@domain>" and "user@domain" formats.
-- Uses the LAST angle-bracket pair (the actual mailbox per RFC 5322),
-- preventing quoted display names with fake addresses from masking the real one.
-- Returns the domain (lowercase) or nil if no email address found.
local function extract_domain_from_header(header_value)
  if not header_value then
    return nil
  end
  -- Find the last <user@domain> in the header (actual mailbox)
  local domain = nil
  local search_start = 1
  while true do
    local s, e, d = string.find(header_value, "<[^>]*@([%w%.%-]+)>", search_start)
    if not s then
      break
    end
    domain = d
    search_start = e + 1
  end
  if domain then
    return string.lower(domain)
  end
  -- Fallback: bare user@domain (no angle brackets)
  domain = string.match(header_value, "@([%w%.%-]+)")
  if domain then
    return string.lower(domain)
  end
  return nil
end

local function bec_callback(task)
  local text = task_text(task)

  -- Gift card scam: gift card keywords + purchase/action keywords
  if contains_any(text, gift_card_terms) and contains_any(text, purchase_terms) then
    return true
  end

  -- Wire transfer fraud: wire/banking terms + urgency
  if contains_any(text, wire_terms) and contains_any(text, urgency_terms) then
    return true
  end

  -- Confidentiality + transaction: "handle discreetly" + "payment"
  if contains_any(text, confidentiality_terms) and contains_any(text, transaction_terms) then
    return true
  end

  -- From/Reply-To domain mismatch (reply-to redirect attack)
  -- Use Rspamd's structured address parsing for MIME headers.
  -- task:get_from("mime") returns MIME From: header addresses (not envelope sender).
  -- task:get_reply_sender() returns the Reply-To: header address (pinned 3.10.2 API).
  -- Both are immune to RFC comment tricks that raw header regex cannot handle.
  local from_domain = nil
  local reply_domain = nil
  if task.get_from then
    -- Request MIME mode explicitly — no-arg defaults to envelope sender
    local from_addrs = task:get_from("mime")
    if from_addrs and from_addrs[1] and from_addrs[1].addr then
      local addr = from_addrs[1].addr
      from_domain = string.match(addr, "@([%w%.%-]+)")
      if from_domain then
        from_domain = string.lower(from_domain)
      end
    end
  end
  -- Rspamd 3.10.2 exposes get_reply_sender, not get_reply_to
  if task.get_reply_sender then
    local reply_addr = task:get_reply_sender()
    if reply_addr then
      reply_domain = string.match(reply_addr, "@([%w%.%-]+)")
      if reply_domain then
        reply_domain = string.lower(reply_domain)
      end
    end
  end
  -- Fallback to raw header parsing if structured API not available
  if not from_domain and task.get_header then
    from_domain = extract_domain_from_header(task:get_header("From"))
  end
  if not reply_domain and task.get_header then
    reply_domain = extract_domain_from_header(task:get_header("Reply-To"))
  end
  if from_domain and reply_domain and from_domain ~= reply_domain then
    -- Only flag if the email also mentions payment/transfer (otherwise
    -- legitimate reply-to mismatches like personal email would fire)
    if contains_any(text, transaction_terms) then
      return true
    end
  end

  return false
end

rspamd_config:register_symbol({
  name = "BEC_PATTERN",
  type = "prefilter",
  score = 7.0,
  description = "Business Email Compromise request language",
  callback = bec_callback,
  group = "bec",
})
