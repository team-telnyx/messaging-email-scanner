# MSG-1795: Rspamd learn API access control
# Controller on port 11334 serves statistics and privileged learn operations.
# Learning always requires the separately injected enable_password credential.

count = 1;
bind_socket = "0.0.0.0:11334";
static_dir = "";

# Injected by entrypoint.sh after hashing the environment-provided secrets.
password = "${CONTROLLER_PASSWORD_HASH}";
enable_password = "${CONTROLLER_ENABLE_PASSWORD_HASH}";

# The packaged worker grants loopback password-less access. An explicit empty
# value is required to override that inherited default; omission is not enough.
secure_ip = [];

# Do not add secure_ip/trusted_ips addresses: Rspamd treats them as
# password-less. Restrict controller reachability to approved internal services
# with the production Service/NetworkPolicy instead.
