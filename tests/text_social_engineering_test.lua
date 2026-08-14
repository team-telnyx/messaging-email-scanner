local test_dir = (arg[0] or ""):match("^(.*)/[^/]+$") or "."
local repo_root = test_dir .. "/.."
local rule_path = repo_root .. "/config/lualib/text_social_engineering.lua"

local registered_symbol
_G.rspamd_config = {
  register_symbol = function(_, definition)
    registered_symbol = definition
    return 1
  end,
}

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function domain_from_addr(addr)
  return addr and addr:match("@([%w%.%-]+)$") or nil
end

local function text_part(content, html)
  return {
    get_content = function()
      return content
    end,
    is_html = function()
      return html == true
    end,
  }
end

local function mime_part(major_type, subtype, options)
  options = options or {}
  return {
    get_type = function()
      return major_type, subtype
    end,
    is_multipart = function()
      return options.multipart == true
    end,
    is_message = function()
      return options.message == true
    end,
    is_attachment = function()
      return options.attachment == true
    end,
    is_text = function()
      return major_type == "text"
    end,
  }
end

local function fake_task(options)
  options = options or {}
  local from_addr = options.from_addr or "vp.finance@external-consulting.net"
  local from_name = options.from_name or "VP Finance"
  local recipient_addr = options.recipient_addr or "accounts@victim.example"
  local parts = options.parts or {
    text_part(options.body or "Please call me immediately today at +1 (312) 555-0198.", false),
  }
  local mime_parts = options.mime_parts or {
    mime_part("text", "plain"),
  }

  return {
    get_subject = function()
      return options.subject or "Urgent request"
    end,
    get_text_parts = function()
      return parts
    end,
    get_parts = function()
      return mime_parts
    end,
    get_content = function()
      return options.body or ""
    end,
    get_urls = function(_, protocols)
      if protocols then
        return options.contact_urls or {}
      end
      return options.urls or {}
    end,
    get_from = function(_, mode)
      if mode ~= "mime" or options.no_from then
        return nil
      end
      return {
        {
          addr = from_addr,
          domain = domain_from_addr(from_addr),
          name = from_name,
        },
      }
    end,
    get_recipients = function(_, mode)
      if options.no_recipients then
        return nil
      end
      if mode == "smtp" and not options.smtp_recipient then
        return nil
      end
      if mode == "mime" or mode == "smtp" then
        return {
          {
            addr = recipient_addr,
            domain = domain_from_addr(recipient_addr),
          },
        }
      end
      return nil
    end,
    get_header = function(_, name)
      if name == "From" then
        if options.no_from then
          return nil
        end
        return string.format("%s <%s>", from_name, from_addr)
      end
      if name == "To" then
        if options.no_recipients then
          return nil
        end
        return recipient_addr
      end
      return nil
    end,
  }
end

local function assert_fires(options, label)
  eq(registered_symbol.callback(fake_task(options)), true, label)
end

local function assert_does_not_fire(options, label)
  eq(registered_symbol.callback(fake_task(options)), false, label)
end

local ok, load_error = pcall(dofile, rule_path)
if not ok then
  error("text_social_engineering rule must load: " .. tostring(load_error))
end

assert(registered_symbol, "TEXT_SOCIAL_ENGINEERING must be registered")
eq(registered_symbol.name, "TEXT_SOCIAL_ENGINEERING", "symbol name")
eq(registered_symbol.type, "normal", "symbol type")
eq(registered_symbol.score, 4.0, "symbol score")

assert_fires({}, "external text-only authority, urgency, and phone request fires")

assert_fires({
  from_name = "CFO",
  subject = "Time-sensitive",
  body = "As soon as possible, please reach me on 312-555-0198.",
}, "CFO plus reach-me request fires case-insensitively")

assert_fires({
  from_name = "Operations Director",
  subject = "Please respond by end of business",
  body = "Contact me by phone at (312) 555 0198.",
}, "director plus end-of-business phone request fires")

assert_fires({
  from_name = "CEO",
  subject = "Urgent",
  body = "As soon\nas possible, please call\tme at 312-555-0198.",
}, "wrapped indicator phrases fire after whitespace normalization")

for _, title in ipairs({ "VP", "CFO", "CEO", "Director", "Manager", "President" }) do
  assert_fires({
    from_name = title,
    subject = "Urgent",
    body = "Please call me at 312.555.0198 today.",
  }, title .. " authority indicator fires")
end

assert_does_not_fire({
  from_addr = "vp.finance@victim.example",
}, "same-domain sender does not fire")

assert_does_not_fire({
  from_name = "Finance Team",
}, "missing authority indicator does not fire")

assert_does_not_fire({
  subject = "Request",
  body = "Please call me at +1 (312) 555-0198 when convenient.",
}, "missing urgency indicator does not fire")

assert_does_not_fire({
  body = "This is urgent today. The quarterly report is attached.",
}, "missing action request does not fire")

assert_does_not_fire({
  body = "Please call me immediately today.",
}, "contact request without a phone number does not fire")

assert_does_not_fire({
  parts = {
    text_part("Please call me immediately today at 312-555-0198.", true),
  },
  mime_parts = {
    mime_part("text", "html"),
  },
}, "HTML email does not fire")

assert_does_not_fire({
  mime_parts = {
    mime_part("multipart", "mixed", { multipart = true }),
    mime_part("text", "plain"),
    mime_part("application", "pdf", { attachment = true }),
  },
}, "plain body with an attachment is not text-only")

assert_does_not_fire({
  mime_parts = {
    mime_part("text", "plain", { attachment = true }),
  },
}, "text attachment is not an inline text-only body")

assert_does_not_fire({
  urls = { "https://example.test/contact" },
}, "email containing a URL does not fire")

assert_does_not_fire({
  contact_urls = { "tel:+13125550198" },
}, "email containing a telephone URL does not fire")

assert_does_not_fire({
  no_from = true,
}, "missing From address does not fire")

assert_does_not_fire({
  no_recipients = true,
}, "missing recipient address does not fire")

assert_does_not_fire({
  from_name = "SVP Finance",
  subject = "Urgent",
  body = "Please call me at 312-555-0198 today.",
}, "VP does not match inside SVP")

assert_does_not_fire({
  from_name = "Managerial Accounting",
  subject = "Urgent",
  body = "Please call me at 312-555-0198 today.",
}, "Manager does not match inside managerial")

print("text_social_engineering_test: PASS")
