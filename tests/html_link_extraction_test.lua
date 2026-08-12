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

local function scan(parts)
  local injected = {}
  local task = {
    get_text_parts = function()
      return parts
    end,
    get_mempool = function()
      return {}
    end,
    inject_url = function(_, url)
      injected[#injected + 1] = url
    end,
  }

  local matched, multiplier, options = symbols.HTML_LINK_MISMATCH.callback(task)
  return {
    task = task,
    injected = injected,
    matched = matched or false,
    multiplier = multiplier,
    options = options,
  }
end

local mismatch = symbols.HTML_LINK_MISMATCH
assert(mismatch, "HTML_LINK_MISMATCH must be registered")
eq(mismatch.type, "prefilter", "registered symbol type")
eq(mismatch.score, 6.0, "registered symbol score")
eq(dependencies.PHISHED_URL_BLOCKLIST.HTML_LINK_MISMATCH, true, "blocklist dependency")

-- Displayed paypal.com masks a different destination domain.
local result = scan({ html_part({ anchor("https://evil.com/login", "paypal.com") }) })
eq(result.matched, true, "display/href mismatch")
eq(result.multiplier, 1.0, "mismatch multiplier")
eq(result.options[1], "display=paypal.com", "mismatch display option")
eq(result.options[2], "href=evil.com", "mismatch href option")
eq(#result.injected, 1, "mismatch href injection count")
eq(tostring(result.injected[1]), "https://evil.com/login", "mismatch href injection")

-- Generic display text is not a mismatch, but the hidden href is still injected
-- so the existing URL blocklist and phishing rules receive it.
result = scan({ html_part({ anchor("https://evil.com/login", "Click here") }) })
eq(result.matched, false, "generic display mismatch")
eq(#result.injected, 1, "generic suspicious href injection count")
eq(tostring(result.injected[1]), "https://evil.com/login", "generic suspicious href injection")

-- Prove an injected hidden href is consumable by the existing phishing heuristic.
result = scan({ html_part({ anchor("https://paypal.com.evil.com/login", "Click here to verify") }) })
result.task.get_urls = function()
  return result.injected
end
local heuristic_matched, _, heuristic_options = phish_heuristics.callback(result.task)
eq(heuristic_matched, true, "hidden href phishing heuristic")
eq(heuristic_options[1], "subdomain_impersonation", "hidden href heuristic reason")

-- A generic link to a known-clean domain is extracted without a mismatch.
result = scan({ html_part({ anchor("https://www.google.com/search", "Click here") }) })
eq(result.matched, false, "clean generic display mismatch")
eq(#result.injected, 1, "clean href injection count")
eq(tostring(result.injected[1]), "https://www.google.com/search", "clean href injection")

-- Plain text parts do not enter the HTML parser or inject URLs.
result = scan({ plain_part() })
eq(result.matched, false, "plain-text mismatch")
eq(#result.injected, 0, "plain-text href injection count")

-- Matching display and destination registered domains are legitimate, including subdomains.
result = scan({ html_part({ anchor("https://login.paypal.com/account", "https://www.paypal.com") }) })
eq(result.matched, false, "matching domain mismatch")
eq(#result.injected, 1, "matching href injection count")

-- Process every anchor, not just the first one.
result = scan({ html_part({
  anchor("https://google.com/", "Google"),
  anchor("https://evil.com/", "paypal.com"),
}) })
eq(result.matched, true, "later anchor mismatch")
eq(#result.injected, 2, "all anchors injected")

eq(extraction.extract_display_domain("Click here"), nil, "generic text has no display domain")
eq(extraction.extract_display_domain("Visit PAYPAL.COM now"), "paypal.com", "display domain normalization")
-- R1 fix: dotted version text must not be treated as a display domain
eq(extraction.extract_display_domain("Version 1.23 release notes"), nil, "version number is not a domain")
eq(extraction.extract_display_domain("Build 2.0.14"), nil, "build number is not a domain")

print("html_link_extraction_test: PASS")
