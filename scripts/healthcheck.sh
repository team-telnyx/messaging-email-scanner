#!/bin/sh
# Health check for Rspamd scanner — uses perl (available in base image)
# Avoids shell interpolation issues by using a heredoc-free single-quote approach
perl -MIO::Socket::INET -e 'my $s=IO::Socket::INET->new(PeerAddr=>"127.0.0.1",PeerPort=>11333,Proto=>"tcp",Timeout=>2) or exit 1; print $s "GET /ping HTTP/1.0\r\nHost: localhost\r\n\r\n"; local $/; my $r=<$s>; exit($r =~ /\r\n\r\npong/ ? 0 : 1)'
