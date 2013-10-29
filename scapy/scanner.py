from scapy.all import *


def scanner(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        if UDP in pkt:
            dnsqr = pkt.getlayer(DNSQR)
            return pkt.sprintf("%IP.src%:%UDP.sport% >>> %IP.dst%:%UDP.dport% ") + dnsqr.sprintf("%qname% %qclass% %qtype%").replace("'","")
try:
    sniff(prn=scanner, filter=None, store=0)
except KeyboardInterrupt:
    exit(0)
