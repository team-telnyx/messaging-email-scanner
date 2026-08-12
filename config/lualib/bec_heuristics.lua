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
  "wire",
  "fund",
}

local function contains_any(text, terms)
  for _, term in ipairs(terms) do
    if string.find(text, term, 1, true) then
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
  local from_header = task:get_header("From")
  local reply_to = task:get_header("Reply-To")
  if from_header and reply_to then
    local from_domain = string.match(from_header, "@([%w%.%-]+)")
    local reply_domain = string.match(reply_to, "@([%w%.%-]+)")
    if from_domain and reply_domain and
       string.lower(from_domain) ~= string.lower(reply_domain) then
      -- Only flag if the email also mentions payment/transfer (otherwise
      -- legitimate reply-to mismatches like personal email would fire)
      if contains_any(text, transaction_terms) then
        return true
      end
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
