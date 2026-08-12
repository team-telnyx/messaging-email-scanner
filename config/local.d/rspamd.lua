-- Load repository-owned Lua prefilter rules from /usr/share/rspamd/lualib.
require "bec_heuristics"
require "phish_url_heuristics"
require "html_link_extraction"
require "homoglyph_detection"
