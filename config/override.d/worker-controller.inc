# Worker controller — ops-only access
# Controller on port 11334 for learn spam/ham, metrics, config management
# Passwords must be hashed (Rspamd requires encrypted passwords)

count = 1;
bind_socket = "0.0.0.0:11334";
secure_ip = "127.0.0.1";
secure_ip = "::1";
static_dir = "";

# Passwords are set via environment variables passed as --var args
# in the Dockerfile entrypoint. See Dockerfile for password hashing.
# password = "{rspamd-controller-password-hash}";
# enable_password = "{rspamd-controller-enable-hash}";
