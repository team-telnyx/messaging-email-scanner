local test_dir = (arg[0] or ""):match("^(.*)/[^/]+$") or "."
local repo_root = test_dir .. "/.."
local rule_path = repo_root .. "/config/lualib/bec_heuristics.lua"

local registered_symbol
_G.rspamd_config = {
  register_symbol = function(_, definition)
    registered_symbol = definition
    return 1
  end,
}

dofile(rule_path)

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function fake_task(subject, body, headers)
  local text_part = {
    get_content = function()
      return body
    end,
  }

  local header_map = headers or {}

  return {
    get_subject = function()
      return subject
    end,
    get_text_parts = function()
      return { text_part }
    end,
    get_text_part = function()
      return text_part
    end,
    get_content = function()
      return body
    end,
    get_header = function(self, name)
      return header_map[name]
    end,
  }
end

local function assert_fires(subject, body, label, headers)
  local matched = registered_symbol.callback(fake_task(subject, body, headers))
  eq(matched, true, label)
end

local function assert_does_not_fire(subject, body, label, headers)
  local matched = registered_symbol.callback(fake_task(subject, body, headers))
  eq(matched, false, label)
end

eq(registered_symbol.name, "BEC_PATTERN", "symbol name")
eq(registered_symbol.type, "prefilter", "symbol type")
eq(registered_symbol.score, 7.0, "symbol score")

assert_fires(
  "Please PURCHASE these today",
  "Can you help with two Amazon gift cards?",
  "gift card plus purchase fires across subject and body"
)

assert_fires(
  "Time-Sensitive Request",
  "Please arrange the SWIFT wire transfer before cutoff.",
  "wire transfer plus urgency fires case-insensitively"
)

assert_fires(
  "Payment request",
  "Handle discreetly while this is being finalized.",
  "confidentiality plus payment fires"
)

assert_does_not_fire(
  "Monthly payment report",
  "Attached are the reconciled invoices and payment history for the quarter.",
  "legitimate payment discussion does not fire"
)

assert_fires(
  "Weekend plans",
  "I made a personal gift card purchase for Mom's birthday.",
  "personal gift card purchase is an accepted false positive"
)

assert_does_not_fire(
  "Thank you",
  "The gift card arrived and is ready to use.",
  "gift card keyword alone does not fire"
)

assert_does_not_fire(
  "Bank setup",
  "The account number is recorded in our approved vendor profile.",
  "wire keyword alone does not fire"
)

assert_does_not_fire(
  "Status update",
  "I'm in a meeting and will review the proposal afterward.",
  "meeting phrase alone does not fire"
)

-- R2: From/Reply-To domain mismatch with transaction context
assert_fires(
  "Re: Payment",
  "Please process the payment to the new bank account.",
  "from/reply-to mismatch with payment fires",
  { ["From"] = "CEO John <john@company.com>", ["Reply-To"] = "hacker@evil.com" }
)

-- R2: From/Reply-To mismatch alone (no transaction context) should NOT fire
assert_does_not_fire(
  "Hello",
  "Just wanted to say hi and catch up.",
  "from/reply-to mismatch without transaction does not fire",
  { ["From"] = "john@company.com", ["Reply-To"] = "john@personal.com" }
)

-- R2: No reply-to header at all should not crash
assert_does_not_fire(
  "Payment update",
  "The payment has been processed.",
  "missing reply-to header does not crash"
)

-- R2: Substring false positive prevention
assert_does_not_fire(
  "Budget review",
  "The buyer requested a refund for the damaged goods.",
  "buyer and refund do not trigger BEC (no word boundary match)"
)

print("bec_heuristics_test: PASS")
