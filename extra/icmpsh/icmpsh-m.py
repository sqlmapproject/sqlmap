#!/usr/bin/python

import socket

import pcapy
from impacket import ImpactDecoder
from impacket import ImpactPacket

ip = ImpactPacket.IP()
ip.set_ip_src('192.168.136.1')
ip.set_ip_dst('192.168.136.132')

def recv_pkts(hdr, data):
    global ip

    x = ImpactDecoder.ICMPDecoder().decode(data)
    print x

    i = raw_input()

    icmp = ImpactPacket.ICMP()
    icmp.set_icmp_type(icmp.ICMP_ECHO)
    icmp.contains(ImpactPacket.Data(i))
    ip.contains(icmp)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    icmp.set_icmp_id(0)
    icmp.set_icmp_cksum(0)
    icmp.auto_checksum = 1

    s.sendto(ip.get_packet(), ('192.168.136.132', 0))

def get_int():
    devs = pcapy.findalldevs()
    i = 0

    for eth in devs:
        print " %d - %s" %(i,devs[i])
        i+=1

    sel = input("Select interface: ")
    dev = devs[sel]

    return dev
 
dev = get_int()
p = pcapy.open_live(dev, 1500, 0, 100)

p.setfilter('icmp')

print "Listening on eth: net=%s, mask=%s\n" % (p.getnet(), p.getmask())

p.loop(-1, recv_pkts)
