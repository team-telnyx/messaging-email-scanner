# Worker controller — ops-only access
# Controller on port 11334 for learn spam/ham, metrics, config management

count = 1;
bind_socket = "0.0.0.0:11334";
secure_ip = "127.0.0.1";
secure_ip = "::1";
static_dir = "";
