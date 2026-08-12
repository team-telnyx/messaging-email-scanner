-- Load repository-owned Lua prefilter rules from /usr/share/rspamd/lualib.
-- HTML link extraction MUST load first so injected URLs are available
-- to phish_url_heuristics and bec_heuristics prefilters that run after.
require "html_link_extraction"
require "bec_heuristics"
require "phish_url_heuristics"
