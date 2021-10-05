#! /usr/bin/python

from scapy.all import *

dst_ip = "172.16.111.103"
src_port = RandShort()
dst_port = 80

pkts = sr1(IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S"), timeout=10)
if pkts is None:
    print("Filtered")
elif(pkts.haslayer(TCP)):
    if(pkts.getlayer(TCP).flags == 0x12):
        send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port, flags="R"), timeout=10)
        print("Open")
    elif (pkts.getlayer(TCP).flags == 0x14):
        print("Closed")
elif(pkts.haslayer(ICMP)):
    if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
        print("Filtered")