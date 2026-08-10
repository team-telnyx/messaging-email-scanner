# Worker controller — ops-only access
# Controller on port 11334 for learn spam/ham, metrics, config management
# Passwords are injected via entrypoint script that generates hashed values

count = 1;
bind_socket = "0.0.0.0:11334";
secure_ip = "127.0.0.1";
secure_ip = "::1";
static_dir = "";

# These are set by the entrypoint script using --var injection
# The entrypoint reads RSPAMD_CONTROLLER_PASSWORD and RSPAMD_CONTROLLER_ENABLE_PASSWORD
# from environment and generates Rspamd password hashes via rspamadm
password = "${CONTROLLER_PASSWORD_HASH}";
enable_password = "${CONTROLLER_ENABLE_PASSWORD_HASH}";
