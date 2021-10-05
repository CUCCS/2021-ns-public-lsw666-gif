#! /usr/bin/python

from scapy.all import *

dst_ip = "172.16.111.103"
src_port = RandShort()
dst_port=80

tcpconnectscan_pkts = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
if tcpconnectscan_pkts is None:
    print("Filtered")
elif(tcpconnectscan_pkts.haslayer(TCP)):
    if(tcpconnectscan_pkts.getlayer(TCP).flags == 0x12):
        print("Open")
    elif (tcpconnectscan_pkts.getlayer(TCP).flags == 0x14):
        print("Closed")