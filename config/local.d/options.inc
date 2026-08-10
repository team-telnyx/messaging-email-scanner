# DNS — use Unbound local resolver for RBL/SURBL
# Public resolvers (1.1.1.1, 8.8.8.8) get blocked by Spamhaus/URIBL
# This file is included in options {} block via local.d/options.inc

dns {
  nameserver = "unbound:53";
  timeout = 5;
  retransmits = 2;
  sockets = 16;
}
