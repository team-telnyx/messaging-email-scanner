local module_dir = os.getenv("HTML_LINK_EXTRACTION_LUA_PATH") or "config/lualib"
package.path = module_dir .. "/?.lua;" .. package.path

local symbols = {}
local dependencies = {}
_G.rspamd_config = {
  register_symbol = function(_, definition)
    symbols[definition.name] = definition
    return definition.name
  end,
  register_dependency = function(_, symbol, dependency)
    dependencies[symbol] = dependencies[symbol] or {}
    dependencies[symbol][dependency] = true
  end,
}

local multi_tld_suffixes = {
  "co.uk", "co.jp", "co.kr", "co.nz", "co.in", "co.za",
  "com.au", "com.br", "com.mx", "com.cn", "com.hk", "com.tw",
  "com.sg", "com.my", "com.ph",
}

local function registered_domain(host)
  host = string.lower(host or ""):gsub("%.$", "")
  for _, suffix in ipairs(multi_tld_suffixes) do
    if host:sub(-#suffix) == suffix then
      local before = host:sub(1, #host - #suffix - 1)
      local label = before:match("([^.]+)$")
      if label then
        return label .. "." .. suffix
      end
    end
  end
  return host:match("([^.]+%.[^.]+)$") or host
end

local function parsed_url(value)
  local normalized = value
  if normalized:match("^//") then
    normalized = "https:" .. normalized
  end

  local host, remainder = normalized:match("^https?://([^/%?#]+)(.*)$")
  if not host then
    return nil
  end
  host = host:gsub("^.-@", ""):gsub(":%d+$", ""):lower()
  local path = (remainder or ""):match("^([^?#]*)") or ""

  return setmetatable({
    get_host = function()
      return host
    end,
    get_tld = function()
      return registered_domain(host)
    end,
    get_path = function()
      return path
    end,
  }, {
    __tostring = function()
      return value
    end,
  })
end

package.preload["rspamd_url"] = function()
  return {
    create = function(_, value)
      return parsed_url(value)
    end,
  }
end

local extraction = require "html_link_extraction"
local phish_heuristics = require "phish_url_heuristics"

local function eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label, tostring(expected), tostring(actual)))
  end
end

local function anchor(href, display_text)
  return {
    get_attribute = function(_, name)
      if name == "href" then
        return href
      end
      return nil
    end,
    get_content = function()
      return display_text
    end,
  }
end

local function html_part(anchors)
  return {
    is_html = function()
      return true
    end,
    get_html = function()
      return {
        foreach_tag = function(_, tag_name, callback)
          eq(tag_name, "a", "HTML parser tag selection")
          for _, tag in ipairs(anchors) do
            if callback(tag, #tostring(tag:get_content() or "")) then
              break
            end
          end
        end,
      }
    end,
  }
end

local function plain_part()
  return {
    is_html = function()
      return false
    end,
    get_html = function()
      error("plain-text parts must not be parsed as HTML")
    end,
  }
end

local function scan(parts, native_urls)
  local task = {
    get_text_parts = function()
      return parts
    end,
    get_urls = function()
      return native_urls or {}
    end,
    get_mempool = function()
      return {}
    end,
  }

  local matched, multiplier, options = symbols.HTML_LINK_MISMATCH.callback(task)
  return {
    task = task,
    matched = matched or false,
    multiplier = multiplier,
    options = options,
  }
end

local mismatch = symbols.HTML_LINK_MISMATCH
assert(mismatch, "HTML_LINK_MISMATCH must be registered")
eq(mismatch.type, "normal", "registered symbol type")
eq(mismatch.score, 6.0, "registered symbol score")

-- Displayed paypal.com masks a different destination domain.
local result = scan({ html_part({ anchor("https://evil.com/login", "paypal.com") }) })
eq(result.matched, true, "display/href mismatch")
eq(result.multiplier, 1.0, "mismatch multiplier")
eq(result.options[1], "display=paypal.com", "mismatch display option")
eq(result.options[2], "href=evil.com", "mismatch href option")

-- Generic display text is not a mismatch (no display domain to compare).
result = scan({ html_part({ anchor("https://evil.com/login", "Click here") }) })
eq(result.matched, false, "generic display mismatch")

-- Prove that a hidden href with subdomain impersonation can be consumed by
-- the existing phishing heuristic when it appears in the native URL set.
result = scan(
  { html_part({ anchor("https://paypal.com.evil.com/login", "Click here to verify") }) },
  { parsed_url("https://paypal.com.evil.com/login") }
)
local heuristic_matched, _, heuristic_options = phish_heuristics.callback(result.task)
eq(heuristic_matched, true, "hidden href phishing heuristic")
eq(heuristic_options[1], "subdomain_impersonation", "hidden href heuristic reason")

-- MSG-1861: Rspamd can expose only the selected text/plain alternative in
-- task:get_urls(). The phishing callback must independently inspect the HTML
-- alternative instead of trusting that native URL set.
result = scan({
  plain_part(),
  html_part({ anchor("https://account.example.org/password-reset", "Reset password") }),
  html_part({
    anchor("https://support.example.org/help", "Get help"),
    anchor("https://paypal.login-secure-portal.com/password-reset", "Reset password"),
  }),
}, {
  parsed_url("https://account.example.org/password-reset"),
})
heuristic_matched, _, heuristic_options = phish_heuristics.callback(result.task)
eq(heuristic_matched, true, "multipart alternative HTML phishing heuristic")
eq(heuristic_options[1], "subdomain_impersonation", "multipart alternative heuristic reason")
eq(heuristic_options[2], "paypal.login-secure-portal.com", "multipart alternative heuristic host")

-- A generic link to a known-clean domain is not a mismatch.
result = scan({ html_part({ anchor("https://www.google.com/search", "Click here") }) })
eq(result.matched, false, "clean generic display mismatch")

-- Plain text parts do not enter the HTML parser.
result = scan({ plain_part() })
eq(result.matched, false, "plain-text mismatch")

-- Matching display and destination registered domains are legitimate, including subdomains.
result = scan({ html_part({ anchor("https://login.paypal.com/account", "https://www.paypal.com") }) })
eq(result.matched, false, "matching domain mismatch")

-- Process every anchor, not just the first one.
result = scan({ html_part({
  anchor("https://google.com/", "Google"),
  anchor("https://evil.com/", "paypal.com"),
}) })
eq(result.matched, true, "later anchor mismatch")

eq(extraction.extract_display_domain("Click here"), nil, "generic text has no display domain")
eq(extraction.extract_display_domain("Visit PAYPAL.COM now"), "paypal.com", "display domain normalization")
-- R1 fix: dotted version text must not be treated as a display domain
eq(extraction.extract_display_domain("Version 1.23 release notes"), nil, "version number is not a domain")
eq(extraction.extract_display_domain("Build 2.0.14"), nil, "build number is not a domain")

print("html_link_extraction_test: PASS")
