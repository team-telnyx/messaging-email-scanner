# Worker proxy — disabled for outbound
# The milter proxy worker (port 11332) is for inbound milter integration.
# For outbound, KumoMTA calls /checkv2 directly via HTTP.
count = -1;
bind_socket = "127.0.0.1:11332";
