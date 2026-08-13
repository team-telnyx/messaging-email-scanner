-- Load repository-owned Lua prefilter rules from /usr/share/rspamd/lualib.
require "bec_heuristics"
require "svg_url_extraction"
require "ical_url_extraction"
require "phish_url_heuristics"
require "html_link_extraction"
require "homoglyph_detection"
require "from_display_impersonation"
require "open_redirect_detection"
