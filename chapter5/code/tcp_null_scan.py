#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

dst_ip = "172.16.111.103"
src_port = RandShort()
dst_port = 80

tcpnullscan_pkts = sr1(
    IP(dst=dst_ip)/TCP(dport=dst_port, flags=""), timeout=10)
if tcpnullscan_pkts is None:
    print("Open|Filtered")
elif(tcpnullscan_pkts.haslayer(TCP)):
    if(tcpnullscan_pkts.getlayer(TCP).flags == 0x14):
        print("Closed")
elif(tcpnullscan_pkts.haslayer(ICMP)):
    if(int(tcpnullscan_pkts.getlayer(ICMP).type) == 3 and int(tcpnullscan_pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
        print("Filtered")